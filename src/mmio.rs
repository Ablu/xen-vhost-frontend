// Copyright 2022-2023 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::OpenOptions;

use vhost::vhost_user::message::{
    VhostUserProtocolFeatures, VHOST_USER_CONFIG_OFFSET,
};
use vhost_user_frontend::{Generic, VirtioDevice};
use vhost_user_frontend::{GuestMemoryMmap, GuestRegionMmap};
use virtio_bindings::virtio_config::{VIRTIO_F_IOMMU_PLATFORM, VIRTIO_F_VERSION_1};
use virtio_bindings::virtio_mmio::{
    VIRTIO_MMIO_CONFIG_GENERATION, VIRTIO_MMIO_DEVICE_FEATURES, VIRTIO_MMIO_DEVICE_FEATURES_SEL,
    VIRTIO_MMIO_DEVICE_ID, VIRTIO_MMIO_DRIVER_FEATURES, VIRTIO_MMIO_DRIVER_FEATURES_SEL,
    VIRTIO_MMIO_INTERRUPT_ACK, VIRTIO_MMIO_INTERRUPT_STATUS, VIRTIO_MMIO_MAGIC_VALUE,
    VIRTIO_MMIO_QUEUE_AVAIL_HIGH, VIRTIO_MMIO_QUEUE_AVAIL_LOW, VIRTIO_MMIO_QUEUE_DESC_HIGH,
    VIRTIO_MMIO_QUEUE_DESC_LOW, VIRTIO_MMIO_QUEUE_NOTIFY, VIRTIO_MMIO_QUEUE_NUM,
    VIRTIO_MMIO_QUEUE_NUM_MAX, VIRTIO_MMIO_QUEUE_READY, VIRTIO_MMIO_QUEUE_SEL,
    VIRTIO_MMIO_QUEUE_USED_HIGH, VIRTIO_MMIO_QUEUE_USED_LOW, VIRTIO_MMIO_STATUS,
    VIRTIO_MMIO_VENDOR_ID, VIRTIO_MMIO_VERSION,
};
use virtio_bindings::virtio_ring::{__virtio16, vring_avail, vring_used, vring_used_elem};
use virtio_queue::{Descriptor, Queue, QueueT};
use vm_memory::ByteValued;
use vm_memory::{
    guest_memory::FileOffset, mmap_xen::{MmapXenFlags, MmapXenGrant}, GuestAddress,
    GuestMemoryAtomic,
};

use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

use super::{device::XenDevice, Error, Result};
use xen_bindings::bindings::{ioreq, IOREQ_READ, IOREQ_WRITE};

struct VirtQueue {
    ready: u32,
    size: u32,
    size_max: u32,
    desc_lo: u32,
    desc_hi: u32,
    avail_lo: u32,
    avail_hi: u32,
    used_lo: u32,
    used_hi: u32,

    // Guest to device
    kick: EventFd,
}

pub struct XenMmio {
    addr: u64,
    magic: [u8; 4],
    version: u8,
    vendor_id: u32,
    status: u32,
    queue_sel: u32,
    device_features_sel: u32,
    driver_features: u64,
    driver_features_sel: u32,
    interrupt_state: u32,
    queues_count: usize,
    queues: Vec<(usize, Queue, EventFd)>,
    vq: Vec<VirtQueue>,
    regions: Vec<GuestRegionMmap>,
}

impl XenMmio {
    pub fn new(gdev: &Generic, addr: u64) -> Result<Self> {
        let sizes = gdev.queue_max_sizes();

        let mut mmio = Self {
            addr,
            magic: [b'v', b'i', b'r', b't'],
            version: 2,
            vendor_id: 0x4d564b4c,
            status: 0,
            queue_sel: 0,
            device_features_sel: 0,
            driver_features: 0,
            driver_features_sel: 0,
            interrupt_state: 0,
            queues_count: sizes.len(),
            queues: Vec::with_capacity(sizes.len()),
            vq: Vec::new(),
            regions: Vec::new(),
        };

        for size in sizes {
            mmio.vq.push(VirtQueue {
                ready: 0,
                size: 0,
                size_max: *size as u32,
                desc_lo: 0,
                desc_hi: 0,
                avail_lo: 0,
                avail_hi: 0,
                used_lo: 0,
                used_hi: 0,
                kick: EventFd::new(EFD_NONBLOCK).unwrap(),
            });
        }

        Ok(mmio)
    }

    fn kick(&self, vq: u64) -> Result<()> {
        // Notify backend
        self.vq[vq as usize]
            .kick
            .write(1)
            .map_err(Error::EventFdWriteFailed)
    }

    pub fn update_interrupt_state(&mut self, mask: u32) {
        self.interrupt_state |= mask;
    }

    fn config_read(&self, ioreq: &mut ioreq, gdev: &Generic, offset: u64) -> Result<()> {
        let mut data: u64 = 0;
        gdev.read_config(offset, &mut data.as_mut_slice()[0..ioreq.size as usize]);
        ioreq.data = data;

        Ok(())
    }

    fn config_write(&self, ioreq: &mut ioreq, gdev: &mut Generic, offset: u64) -> Result<()> {
        gdev.write_config(offset, &ioreq.data.to_ne_bytes()[0..ioreq.size as usize]);
        Ok(())
    }

    fn io_read(&self, ioreq: &mut ioreq, dev: &XenDevice, offset: u64) -> Result<()> {
        let vq = &self.vq[self.queue_sel as usize];
        let gdev = dev.gdev.lock().unwrap();

        ioreq.data = match offset as u32 {
            VIRTIO_MMIO_MAGIC_VALUE => u32::from_le_bytes(self.magic),
            VIRTIO_MMIO_VERSION => self.version as u32,
            VIRTIO_MMIO_DEVICE_ID => gdev.device_type(),
            VIRTIO_MMIO_VENDOR_ID => self.vendor_id,
            VIRTIO_MMIO_STATUS => self.status,
            VIRTIO_MMIO_INTERRUPT_STATUS => self.interrupt_state,
            VIRTIO_MMIO_QUEUE_NUM_MAX => vq.size_max,
            VIRTIO_MMIO_DEVICE_FEATURES => {
                if self.device_features_sel > 1 {
                    return Err(Error::InvalidFeatureSel(self.device_features_sel));
                }

                let mut features = gdev.device_features();
                features |= 1 << VIRTIO_F_VERSION_1;
                features |= 1 << VIRTIO_F_IOMMU_PLATFORM;
                (features >> (32 * self.device_features_sel)) as u32
            }
            VIRTIO_MMIO_QUEUE_READY => vq.ready,
            VIRTIO_MMIO_QUEUE_DESC_LOW => vq.desc_lo,
            VIRTIO_MMIO_QUEUE_DESC_HIGH => vq.desc_hi,
            VIRTIO_MMIO_QUEUE_USED_LOW => vq.used_lo,
            VIRTIO_MMIO_QUEUE_USED_HIGH => vq.used_hi,
            VIRTIO_MMIO_QUEUE_AVAIL_LOW => vq.avail_lo,
            VIRTIO_MMIO_QUEUE_AVAIL_HIGH => vq.avail_hi,
            VIRTIO_MMIO_CONFIG_GENERATION => {
                // TODO
                0
            }

            _ => return Err(Error::InvalidMmioAddr("read", offset)),
        } as u64;

        Ok(())
    }

    fn io_write(&mut self, ioreq: &ioreq, dev: &XenDevice, offset: u64) -> Result<()> {
        let vq = &mut self.vq[self.queue_sel as usize];

        match offset as u32 {
            VIRTIO_MMIO_DEVICE_FEATURES_SEL => self.device_features_sel = ioreq.data as u32,
            VIRTIO_MMIO_DRIVER_FEATURES_SEL => self.driver_features_sel = ioreq.data as u32,
            VIRTIO_MMIO_QUEUE_SEL => self.queue_sel = ioreq.data as u32,
            VIRTIO_MMIO_STATUS => self.status = ioreq.data as u32,
            VIRTIO_MMIO_QUEUE_NUM => vq.size = ioreq.data as u32,
            VIRTIO_MMIO_QUEUE_DESC_LOW => vq.desc_lo = ioreq.data as u32,
            VIRTIO_MMIO_QUEUE_DESC_HIGH => vq.desc_hi = ioreq.data as u32,
            VIRTIO_MMIO_QUEUE_USED_LOW => vq.used_lo = ioreq.data as u32,
            VIRTIO_MMIO_QUEUE_USED_HIGH => vq.used_hi = ioreq.data as u32,
            VIRTIO_MMIO_QUEUE_AVAIL_LOW => vq.avail_lo = ioreq.data as u32,
            VIRTIO_MMIO_QUEUE_AVAIL_HIGH => vq.avail_hi = ioreq.data as u32,
            VIRTIO_MMIO_INTERRUPT_ACK => {
                self.interrupt_state &= !(ioreq.data as u32);
            }
            VIRTIO_MMIO_DRIVER_FEATURES => {
                self.driver_features |=
                    ((ioreq.data as u32) as u64) << (32 * self.driver_features_sel);

                if self.driver_features_sel == 1 {
                    if (self.driver_features & (1 << VIRTIO_F_VERSION_1)) == 0 {
                        return Err(Error::MmioLegacyNotSupported);
                    }
                } else {
                    // Guest sends feature sel 1 first, followed by 0. Once that is done, lets
                    // negotiate features.
                    dev.gdev
                        .lock()
                        .unwrap()
                        .negotiate_features(
                            self.driver_features,
                            VhostUserProtocolFeatures::XEN_MMAP,
                        )
                        .map_err(Error::VhostFrontendError)?;
                }
            }
            VIRTIO_MMIO_QUEUE_READY => {
                if ioreq.data == 1 {
                    self.init_vq(dev.guest.fe_domid)?;

                    // Wait for all virtqueues to get initialized.
                    if self.queues.len() == self.queues_count {
                        self.activate_device(dev)?;
                    }
                } else {
                    self.destroy_vq();
                }
            }
            VIRTIO_MMIO_QUEUE_NOTIFY => self.kick(ioreq.data)?,

            _ => return Err(Error::InvalidMmioAddr("write", offset)),
        }

        Ok(())
    }

    fn map_region(&mut self, addr: u64, size: usize, domid: u16, flags: u32) -> Result<()> {
        let addr = GuestAddress(addr);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/xen/gntdev")
            .unwrap();
        let file_offset = Some(FileOffset::new(file, 0));

        let map = MmapXenGrant::new_with(domid as u32, addr, flags);

        let region = GuestRegionMmap::from_range_with_map(map, addr, size, file_offset).unwrap();
        self.regions.push(region);

        Ok(())
    }

    fn map_queue_regions(
        &mut self,
        queue: Queue,
        vq_size: usize,
        kick: EventFd,
        domid: u16,
    ) -> Result<()> {
        let mut size = vq_size * std::mem::size_of::<Descriptor>();
        self.map_region(queue.desc_table(), size, domid, MmapXenFlags::GRANT.bits())?;

        size = vq_size * std::mem::size_of::<__virtio16>();
        size += std::mem::size_of::<vring_avail>();
        self.map_region(queue.avail_ring(), size, domid, MmapXenFlags::GRANT.bits())?;

        size = vq_size * std::mem::size_of::<vring_used_elem>();
        size += std::mem::size_of::<vring_used>();
        // Extra 2 bytes for vring_used_elem at the end of used ring
        size += std::mem::size_of::<__virtio16>();
        self.map_region(queue.used_ring(), size, domid, MmapXenFlags::GRANT.bits())?;

        self.map_region(queue.used_ring() + size as u64 + 0x1000 - 6, 0x100000, domid, MmapXenFlags::GRANT.bits() | MmapXenFlags::NO_ADVANCE_MAP.bits())?;

        self.queues.push((self.queue_sel as usize, queue, kick));

        Ok(())
    }

    fn init_vq(&mut self, domid: u16) -> Result<()> {
        let vq = &mut self.vq[self.queue_sel as usize];
        let kick = vq.kick.try_clone().unwrap();
        let size = vq.size;

        let desc = ((vq.desc_hi as u64) << 32) | vq.desc_lo as u64;
        let avail = ((vq.avail_hi as u64) << 32) | vq.avail_lo as u64;
        let used = ((vq.used_hi as u64) << 32) | vq.used_lo as u64;

        if desc == 0 || avail == 0 || used == 0 {
            panic!();
        }

        let mut queue = Queue::new(size as u16).unwrap();
        queue.set_desc_table_address(Some((desc & 0xFFFFFFFF) as u32), Some((desc >> 32) as u32));
        queue.set_avail_ring_address(
            Some((avail & 0xFFFFFFFF) as u32),
            Some((avail >> 32) as u32),
        );
        queue.set_used_ring_address(Some((used & 0xFFFFFFFF) as u32), Some((used >> 32) as u32));
        queue.set_next_avail(0);

        vq.ready = 1;
        self.map_queue_regions(queue, size as usize, kick, domid)
    }

    fn destroy_vq(&mut self) {
        self.queues.drain(..);
    }

    fn mem(&mut self) -> GuestMemoryAtomic<GuestMemoryMmap> {
        GuestMemoryAtomic::new(
            GuestMemoryMmap::from_regions(self.regions.drain(..).collect()).unwrap(),
        )
    }

    fn activate_device(&mut self, dev: &XenDevice) -> Result<()> {
        dev.gdev
            .lock()
            .unwrap()
            .activate(self.mem(), dev.interrupt(), self.queues.drain(..).collect())
            .map_err(Error::VhostFrontendActivateError)
    }

    pub fn io_event(&mut self, ioreq: &mut ioreq, dev: &XenDevice) -> Result<()> {
        let mut offset = ioreq.addr - self.addr;

        if offset >= VHOST_USER_CONFIG_OFFSET as u64 {
            offset -= VHOST_USER_CONFIG_OFFSET as u64;
            let gdev = &mut dev.gdev.lock().unwrap();

            match ioreq.dir() as u32 {
                IOREQ_READ => self.config_read(ioreq, gdev, offset),
                IOREQ_WRITE => self.config_write(ioreq, gdev, offset),
                _ => Err(Error::InvalidMmioDir(ioreq.dir())),
            }
        } else {
            match ioreq.dir() as u32 {
                IOREQ_READ => self.io_read(ioreq, dev, offset),
                IOREQ_WRITE => self.io_write(ioreq, dev, offset),
                _ => Err(Error::InvalidMmioDir(ioreq.dir())),
            }
        }
    }
}
