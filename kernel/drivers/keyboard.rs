use crate::drivers::serial::Spinlock;

const SCANCODE_MAP: [u8; 128] = [
    0,  27, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'-', b'=', b'\x08',
    b'\t', b'q', b'w', b'e', b'r', b't', b'y', b'u', b'i', b'o', b'p', b'[', b']', b'\n',
    0, // control
    b'a', b's', b'd', b'f', b'g', b'h', b'j', b'k', b'l', b';', b'\'', b'`',
    0, // left shift
    b'\\', b'z', b'x', b'c', b'v', b'b', b'n', b'm', b',', b'.', b'/',
    0, // right shift
    b'*',
    0, // alt
    b' ', // space
    0, // caps lock
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // F1-F10
    0, // num lock
    0, // scroll lock
    0, // home
    0, // up
    0, // page up
    b'-',
    0, // left
    0,
    0, // right
    b'+',
    0, // end
    0, // down
    0, // page down
    0, // insert
    0, // delete
    0, 0, 0,
    0, // F11
    0, // F12
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
];

pub struct KbdBuffer {
    data: [u8; 64],
    head: usize,
    tail: usize,
    count: usize,
}

impl KbdBuffer {
    const fn new() -> Self {
        Self {
            data: [0; 64],
            head: 0,
            tail: 0,
            count: 0,
        }
    }
    
    pub fn push(&mut self, val: u8) {
        if self.count < 64 {
            self.data[self.tail] = val;
            self.tail = (self.tail + 1) % 64;
            self.count += 1;
        }
    }
    
    pub fn pop(&mut self) -> Option<u8> {
        if self.count > 0 {
            let val = self.data[self.head];
            self.head = (self.head + 1) % 64;
            self.count -= 1;
            Some(val)
        } else {
            None
        }
    }
}

pub static KBD_BUFFER: Spinlock<KbdBuffer> = Spinlock::new(KbdBuffer::new());

unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    core::arch::asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags));
    value
}

pub fn try_read() -> Option<u8> {
    KBD_BUFFER.lock().pop()
}

#[no_mangle]
pub extern "C" fn keyboard_isr() {
    unsafe {
        let scancode = inb(0x60);
        if scancode < 128 {
            let ascii = SCANCODE_MAP[scancode as usize];
            if ascii != 0 {
                KBD_BUFFER.lock().push(ascii);
            }
        }
    }
    crate::shell::KBD_IRQS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    crate::interrupts::pic_eoi();
}
