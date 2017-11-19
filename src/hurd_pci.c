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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/mman.h>
#include <string.h>
#include <strings.h>
#include <hurd.h>
#include <hurd/pci_conf.h>
#include <hurd/paths.h>

#include "x86_pci.h"
#include "pciaccess.h"
#include "pciaccess_private.h"

/* Server path */
#define _SERVERS_PCI_CONF	_SERVERS_BUS "/pci"

/* File names */
#define FILE_CONFIG_NAME "config"
#define FILE_ROM_NAME "rom"

/* Level in the fs tree */
typedef enum {
    LEVEL_NONE,
    LEVEL_DOMAIN,
    LEVEL_BUS,
    LEVEL_DEV,
    LEVEL_FUNC
} tree_level;

struct pci_system_hurd {
    struct pci_system system;
};

/* Returns the number of regions (base address registers) the device has */
static int
pci_device_hurd_get_num_regions(uint8_t header_type)
{
    switch (header_type & 0x7f) {
	case 0:
	    return 6;
	case 1:
	    return 2;
	case 2:
	    return 1;
	default:
	    fprintf(stderr,"unknown header type %02x\n", header_type);
	    return 0;
    }
}

/* Masks out the flag bigs of the base address register value */
static uint32_t
get_map_base( uint32_t val )
{
    if (val & 0x01)
	return val & ~0x03;
    else
	return val & ~0x0f;
}

/* Returns the size of a region based on the all-ones test value */
static unsigned
get_test_val_size( uint32_t testval )
{
    unsigned size = 1;

    if (testval == 0)
	return 0;

    /* Mask out the flag bits */
    testval = get_map_base( testval );
    if (!testval)
	return 0;

    while ((testval & 1) == 0) {
	size <<= 1;
	testval >>= 1;
    }

    return size;
}

static int
pci_device_hurd_probe(struct pci_device *dev)
{
    uint8_t irq, hdrtype;
    int err, i, bar;
    char server[NAME_MAX];
    struct stat romst;

    /* Many of the fields were filled in during initial device enumeration.
     * At this point, we need to fill in regions, rom_size, and irq.
     */

    err = pci_device_cfg_read_u8(dev, &irq, PCI_IRQ);
    if (err)
        return err;
    dev->irq = irq;

    err = pci_device_cfg_read_u8(dev, &hdrtype, PCI_HDRTYPE);
    if (err)
        return err;

    bar = 0x10;
    for (i = 0; i < pci_device_hurd_get_num_regions(hdrtype); i++, bar += 4) {
        uint32_t addr, testval;

        /* Get the base address */
        err = pci_device_cfg_read_u32(dev, &addr, bar);
        if (err != 0)
            continue;

        /* Test write all ones to the register, then restore it. */
        err = pci_device_cfg_write_u32(dev, 0xffffffff, bar);
        if (err != 0)
            continue;
        pci_device_cfg_read_u32(dev, &testval, bar);
        err = pci_device_cfg_write_u32(dev, addr, bar);

        if (addr & 0x01)
            dev->regions[i].is_IO = 1;
        if (addr & 0x04)
            dev->regions[i].is_64 = 1;
        if (addr & 0x08)
            dev->regions[i].is_prefetchable = 1;

        /* Set the size */
        dev->regions[i].size = get_test_val_size(testval);

        /* Set the base address value */
        if (dev->regions[i].is_64) {
            uint32_t top;

            err = pci_device_cfg_read_u32(dev, &top, bar + 4);
            if (err != 0)
                continue;

            dev->regions[i].base_addr = ((uint64_t)top << 32)
                                         | get_map_base(addr);
            bar += 4;
            i++;
        }
        else {
            dev->regions[i].base_addr = get_map_base(addr);
        }
    }

    /* If it's a VGA device, read the rom size from the fs tree
     */
    if ((dev->device_class & 0x00ffff00) ==
        ((PCIC_DISPLAY << 16) | (PCIS_DISPLAY_VGA << 8)))
    {
        snprintf(server, NAME_MAX, "%s/%04x/%02x/%02x/%01u/%s",
                 _SERVERS_PCI_CONF, dev->domain, dev->bus, dev->dev,
                 dev->func, FILE_ROM_NAME);
        err = lstat(server, &romst);
        if (err)
            return err;

        dev->rom_size = romst.st_size;
    }

    return 0;
}

/*
 * Read 'size' bytes from B/D/F + reg and store them in 'buf'.
 *
 * It's assumed that 'size' bytes are allocated in 'buf'
 */
static int
pciclient_cfg_read(mach_port_t device_port, int bus, int dev, int func,
                   int reg, char *buf, size_t * nbytes)
{
    int err;
    size_t nread;
    char *data;

    data = buf;
    nread = *nbytes;
    err = pci_conf_read(device_port, bus, dev, func, reg, &data, &nread,
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
pciclient_cfg_write(mach_port_t device_port, int bus, int dev, int func,
                    int reg, char *buf, size_t * nbytes)
{
    int err;
    size_t nwrote;

    err = pci_conf_write(device_port, bus, dev, func, reg, buf, *nbytes,
                         &nwrote);

    if (!err)
        *nbytes = nwrote;

    return err;
}

/*
 * Read up to `size' bytes from `dev' configuration space to `data' starting
 * at `offset'. Write the amount on read bytes in `bytes_read'.
 */
static int
pci_device_hurd_read(struct pci_device *dev, void *data,
    pciaddr_t offset, pciaddr_t size, pciaddr_t *bytes_read)
{
    int err;
    struct pci_device_private *d;

    *bytes_read = 0;
    d = (struct pci_device_private *)dev;
    while (size > 0) {
        size_t toread = 1 << (ffs(0x4 + (offset & 0x03)) - 1);
        if (toread > size)
            toread = size;

        err = pciclient_cfg_read(d->device_port, dev->bus, dev->dev,
                                 dev->func, offset, (char*)data, &toread);
        if (err)
            return err;

        offset += toread;
        data = (char*)data + toread;
        size -= toread;
        *bytes_read += toread;
    }
    return 0;
}

/*
 * Write up to `size' bytes from `data' to `dev' configuration space starting
 * at `offset'. Write the amount on written bytes in `bytes_written'.
 */
static int
pci_device_hurd_write(struct pci_device *dev, const void *data,
    pciaddr_t offset, pciaddr_t size, pciaddr_t *bytes_written)
{
    int err;
    struct pci_device_private *d;

    *bytes_written = 0;
    d = (struct pci_device_private *)dev;
    while (size > 0) {
        size_t towrite = 4;
        if (towrite > size)
            towrite = size;
        if (towrite > 4 - (offset & 0x3))
            towrite = 4 - (offset & 0x3);

        err = pciclient_cfg_write(d->device_port, dev->bus, dev->dev,
                                  dev->func, offset, (char*)data, &towrite);
        if (err)
            return err;

        offset += towrite;
        data = (const char*)data + towrite;
        size -= towrite;
        *bytes_written += towrite;
    }
    return 0;
}

/*
 * Copy the device's firmware in `buffer'
 */
static int
pci_device_hurd_read_rom(struct pci_device * dev, void * buffer)
{
    void *rom;
    int romfd;
    char server[NAME_MAX];

    if ((dev->device_class & 0x00ffff00) !=
          ((PCIC_DISPLAY << 16) | ( PCIS_DISPLAY_VGA << 8))) {
        return ENOSYS;
    }

    snprintf(server, NAME_MAX, "%s/%04x/%02x/%02x/%01u/%s", _SERVERS_PCI_CONF,
             dev->domain, dev->bus, dev->dev, dev->func, FILE_ROM_NAME);
    romfd = open(server, O_RDONLY | O_CLOEXEC);
    if (romfd == -1)
        return errno;

    rom = mmap(NULL, dev->rom_size, PROT_READ, 0, romfd, 0);
    if (rom == MAP_FAILED) {
        close(romfd);
        return errno;
    }

    memcpy(buffer, rom, dev->rom_size);

    munmap(rom, dev->rom_size);
    close(romfd);

    return 0;
}

/*
 * Each device has its own server where send RPC's to.
 *
 * Deallocate the port before destroying the device.
 */
static void
pci_device_hurd_destroy(struct pci_device *dev)
{
    struct pci_device_private *d = (struct pci_device_private*) dev;

    mach_port_deallocate (mach_task_self (), d->device_port);
}

/* Walk through the FS tree to see what is allowed for us */
static int
enum_devices(const char *parent, struct pci_device_private **device,
                int domain, int bus, int dev, int func, tree_level lev)
{
    int err, ret;
    DIR *dir;
    struct dirent *entry;
    char path[NAME_MAX];
    char server[NAME_MAX];
    uint32_t reg;
    size_t toread;
    mach_port_t device_port;

    dir = opendir(parent);
    if (!dir)
        return errno;

    while ((entry = readdir(dir)) != 0) {
        snprintf(path, NAME_MAX, "%s/%s", parent, entry->d_name);
        if (entry->d_type == DT_DIR) {
            if (!strncmp(entry->d_name, ".", NAME_MAX)
                || !strncmp(entry->d_name, "..", NAME_MAX))
                continue;

            errno = 0;
            ret = strtol(entry->d_name, 0, 16);
            if (errno)
                return errno;

            /*
             * We found a valid directory.
             * Update the address and switch to the next level.
             */
            switch (lev) {
            case LEVEL_DOMAIN:
                domain = ret;
                break;
            case LEVEL_BUS:
                bus = ret;
                break;
            case LEVEL_DEV:
                dev = ret;
                break;
            case LEVEL_FUNC:
                func = ret;
                break;
            default:
                return -1;
            }

            err = enum_devices(path, device, domain, bus, dev, func, lev+1);
            if (err == EPERM)
                continue;
        }
        else {
            if (strncmp(entry->d_name, FILE_CONFIG_NAME, NAME_MAX))
                /* We are looking for the config file */
                continue;

            /* We found an available virtual device, add it to our list */
            snprintf(server, NAME_MAX, "%s/%04x/%02x/%02x/%01u/%s",
                     _SERVERS_PCI_CONF, domain, bus, dev, func, entry->d_name);
            device_port = file_name_lookup(server, 0, 0);
            if (device_port == MACH_PORT_NULL)
                return errno;

            toread = sizeof(reg);
            err = pciclient_cfg_read(device_port, bus, dev, func,
                                     PCI_VENDOR_ID, (char*)&reg, &toread);
            if (err)
                return err;
            if (toread != sizeof(reg))
                return -1;

            (*device)->base.domain = domain;
            (*device)->base.bus = bus;
            (*device)->base.dev = dev;
            (*device)->base.func = func;
            (*device)->base.vendor_id = PCI_VENDOR(reg);
            (*device)->base.device_id = PCI_DEVICE(reg);

            toread = sizeof(reg);
            err = pciclient_cfg_read(device_port, bus, dev, func, PCI_CLASS,
                                     (char*)&reg, &toread);
            if (err)
                return err;
            if (toread != sizeof(reg))
                return -1;

            (*device)->base.device_class = reg >> 8;
            (*device)->base.revision = reg & 0xFF;

            toread = sizeof(reg);
            err = pciclient_cfg_read(device_port, bus, dev, func,
                                     PCI_SUB_VENDOR_ID, (char*)&reg, &toread);
            if (err)
                return err;
            if (toread != sizeof(reg))
                return -1;

            (*device)->base.subvendor_id = PCI_VENDOR(reg);
            (*device)->base.subdevice_id = PCI_DEVICE(reg);

            (*device)->device_port = device_port;

            (*device)++;
        }
    }

    return 0;
}

static const struct pci_system_methods hurd_pci_methods = {
    .destroy = pci_system_x86_destroy,
    .destroy_device = pci_device_hurd_destroy,
    .read_rom = pci_device_hurd_read_rom,
    .probe = pci_device_hurd_probe,
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
    int err;
    struct pci_system_hurd *pci_sys_hurd;
    size_t ndevs;
    mach_port_t pci_server_port;

    err = x86_enable_io();
    if (err)
        return err;

    pci_sys_hurd = calloc(1, sizeof(struct pci_system_hurd));
    if (pci_sys_hurd == NULL) {
        x86_disable_io();
        return ENOMEM;
    }
    pci_sys = &pci_sys_hurd->system;

    pci_sys->methods = &hurd_pci_methods;

    pci_server_port = file_name_lookup(_SERVERS_PCI_CONF, 0, 0);
    if (pci_server_port == MACH_PORT_NULL)
        return errno;

    /* The server gives us the number of available devices for us */
    err = pci_conf_get_ndevs (pci_server_port, &ndevs);
    if (err) {
        mach_port_deallocate (mach_task_self (), pci_server_port);
        return err;
    }
    mach_port_deallocate (mach_task_self (), pci_server_port);

    pci_sys->num_devices = ndevs;
    pci_sys->devices = calloc(ndevs, sizeof(struct pci_device_private));
    if (pci_sys->devices == NULL) {
        x86_disable_io();
        free(pci_sys_hurd);
        pci_sys = NULL;
        return ENOMEM;
    }

    device = pci_sys->devices;
    err = enum_devices(_SERVERS_PCI_CONF, &device, -1, -1, -1, -1,
                       LEVEL_DOMAIN);
    if (err)
        return err;

    return 0;
}
