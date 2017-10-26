/*
 * Copyright (c) 2017, Joan Lledó
 * Copyright (c) 2009, 2012 Samuel Thibault
 * Heavily inspired from the freebsd, netbsd, and openbsd backends
 * (C) Copyright Eric Anholt 2006
 * (C) Copyright IBM Corporation 2006
 * Copyright (c) 2008 Juan Romero Pardines
 * Copyright (c) 2008 Mark Kettenis
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <strings.h>
#include <hurd.h>
#include <hurd/pci_conf.h>
#include <hurd/paths.h>

#include "x86_pci.h"
#include "pciaccess.h"
#include "pciaccess_private.h"

struct pci_system_hurd {
    struct pci_system system;
};

/* Server port */
mach_port_t pci_server_port = MACH_PORT_NULL;

/* Get the server port */
static int
init_client(void)
{
    int ret = 0;
    pci_server_port = file_name_lookup(_SERVERS_PCI_CONF, 0, 0);

    if (pci_server_port == MACH_PORT_NULL)
        ret = errno;

    return ret;
}

/*
 * Read 'size' bytes from B/D/F + reg and store them in 'buf'.
 *
 * It's assumed that 'size' bytes are allocated in 'buf'
 */
static int
pciclient_cfg_read(int bus, int dev, int func, int reg, char *buf,
                    size_t * nbytes)
{
    error_t err;
    size_t nread;
    char *data;

    data = buf;
    nread = *nbytes;
    err = pci_conf_read(pci_server_port, bus, dev, func, reg, &data, &nread,
                         *nbytes);
    if (err)
        return err;

    if (data != buf) {
        if (nread > *nbytes)	/* Sanity check for bogus server.  */ {
            vm_deallocate(mach_task_self(), (vm_address_t) data, nread);
            return EGRATUITOUS;
        }

        memcpy(buf, data, nread);
        vm_deallocate(mach_task_self(), (vm_address_t)data, nread);
    }

    *nbytes = nread;

    return 0;
}

/* Write 'size' bytes from 'buf' to B/D/F + reg */
static int
pciclient_cfg_write(int bus, int dev, int func, int reg, char *buf,
                     size_t * nbytes)
{
    error_t err;
    size_t nwrote;

    err = pci_conf_write(pci_server_port, bus, dev, func, reg, buf, *nbytes,
                        &nwrote);

    if (!err)
        *nbytes = nwrote;

    return err;
}

static int
pci_nfuncs(struct pci_system_hurd *pci_sys_hurd, int bus, int dev)
{
    uint8_t hdr;
    size_t size;
    int err;

    size = sizeof(hdr);
    err = pciclient_cfg_read(bus, dev, 0, PCI_HDRTYPE, (char*)&hdr, &size);

    if (err)
        return err;

    if(size != sizeof(hdr))
        return EIO;

    return hdr & 0x80 ? 8 : 1;
}

static int
pci_device_hurd_read(struct pci_device *dev, void *data,
    pciaddr_t offset, pciaddr_t size, pciaddr_t *bytes_read)
{
    int err;

    *bytes_read = 0;
    while (size > 0) {
        size_t toread = 1 << (ffs(0x4 + (offset & 0x03)) - 1);
        if (toread > size)
            toread = size;

        err = pciclient_cfg_read(dev->bus, dev->dev, dev->func, offset,
                                 (char*)data, &toread);
        if (err)
            return err;

        offset += toread;
        data = (char*)data + toread;
        size -= toread;
        *bytes_read += toread;
    }
    return 0;
}

static int
pci_device_hurd_write(struct pci_device *dev, const void *data,
    pciaddr_t offset, pciaddr_t size, pciaddr_t *bytes_written)
{
    int err;

    *bytes_written = 0;
    while (size > 0) {
        size_t towrite = 4;
        if (towrite > size)
            towrite = size;
        if (towrite > 4 - (offset & 0x3))
            towrite = 4 - (offset & 0x3);

        err = pciclient_cfg_write(dev->bus, dev->dev, dev->func, offset,
                                  (char*)data, &towrite);
        if (err)
            return err;

        offset += towrite;
        data = (const char*)data + towrite;
        size -= towrite;
        *bytes_written += towrite;
    }
    return 0;
}

static const struct pci_system_methods hurd_pci_methods = {
    .destroy = pci_system_x86_destroy,
    .read_rom = pci_device_x86_read_rom,
    .probe = pci_device_x86_probe,
    .map_range = pci_device_x86_map_range,
    .unmap_range = pci_device_x86_unmap_range,
    .read = pci_device_hurd_read,
    .write = pci_device_hurd_write,
    .fill_capabilities = pci_fill_capabilities_generic,
    .open_legacy_io = pci_device_x86_open_legacy_io,
    .close_io = pci_device_x86_close_io,
    .read32 = pci_device_x86_read32,
    .read16 = pci_device_x86_read16,
    .read8 = pci_device_x86_read8,
    .write32 = pci_device_x86_write32,
    .write16 = pci_device_x86_write16,
    .write8 = pci_device_x86_write8,
    .map_legacy = pci_device_x86_map_legacy,
    .unmap_legacy = pci_device_x86_unmap_legacy,
};

_pci_hidden int
pci_system_hurd_create(void)
{
    struct pci_device_private *device;
    int ret, bus, dev, ndevs, func, nfuncs;
    struct pci_system_hurd *pci_sys_hurd;
    uint32_t reg;
    size_t toread;

    ret = x86_enable_io();
    if (ret)
        return ret;

    ret = init_client();
    if (ret)
        return ret;

    pci_sys_hurd = calloc(1, sizeof(struct pci_system_hurd));
    if (pci_sys_hurd == NULL) {
        x86_disable_io();
        return ENOMEM;
    }
    pci_sys = &pci_sys_hurd->system;

    pci_sys->methods = &hurd_pci_methods;

    ndevs = 0;
    for (bus = 0; bus < 256; bus++) {
        for (dev = 0; dev < 32; dev++) {
            nfuncs = pci_nfuncs(pci_sys_hurd, bus, dev);
            for (func = 0; func < nfuncs; func++) {
                toread = sizeof(reg);
                if (pciclient_cfg_read(bus, dev, func, PCI_VENDOR_ID,
                                       (char*)&reg, &toread) != 0)
                     continue;
                if (PCI_VENDOR(reg) == PCI_VENDOR_INVALID ||
                    PCI_VENDOR(reg) == 0 ||
                    toread != sizeof(reg))
                    continue;
                ndevs++;
            }
        }
    }

    pci_sys->num_devices = ndevs;
    pci_sys->devices = calloc(ndevs, sizeof(struct pci_device_private));
    if (pci_sys->devices == NULL) {
        x86_disable_io();
        free(pci_sys_hurd);
        pci_sys = NULL;
        return ENOMEM;
    }

    device = pci_sys->devices;
    for (bus = 0; bus < 256; bus++) {
        for (dev = 0; dev < 32; dev++) {
            nfuncs = pci_nfuncs(pci_sys_hurd, bus, dev);
            for (func = 0; func < nfuncs; func++) {
                toread = sizeof(reg);
                if (pciclient_cfg_read(bus, dev, func, PCI_VENDOR_ID,
                                       (char*)&reg, &toread) != 0)
                    continue;
                if (PCI_VENDOR(reg) == PCI_VENDOR_INVALID ||
                    PCI_VENDOR(reg) == 0 ||
                    toread != sizeof(reg))
                    continue;
                device->base.domain = 0;
                device->base.bus = bus;
                device->base.dev = dev;
                device->base.func = func;
                device->base.vendor_id = PCI_VENDOR(reg);
                device->base.device_id = PCI_DEVICE(reg);

                toread = sizeof(reg);
                if (pciclient_cfg_read(bus, dev, func, PCI_CLASS,
                                       (char*)&reg,&toread) != 0)
                    continue;
                device->base.device_class = reg >> 8;
                device->base.revision = reg & 0xFF;

                toread = sizeof(reg);
                if (pciclient_cfg_read(bus, dev, func, PCI_SUB_VENDOR_ID,
                                       (char*)&reg, &toread) != 0)
                    continue;
                if (toread != sizeof(reg))
                    continue;
                device->base.subvendor_id = PCI_VENDOR(reg);
                device->base.subdevice_id = PCI_DEVICE(reg);

                device++;
            }
        }
    }

    return 0;
}
