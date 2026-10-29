#!/usr/bin/env python3
# Minimal PE reporter: machine, sections (name/vsz/rsz/flags), TLS presence, entry.
import sys, struct
def u16(b,o): return struct.unpack_from('<H',b,o)[0]
def u32(b,o): return struct.unpack_from('<I',b,o)[0]
def main(path):
    b=open(path,'rb').read()
    pe=u32(b,0x3c)
    machine=u16(b,pe+4); nsec=u16(b,pe+6); optsz=u16(b,pe+20)
    magic=u16(b,pe+24); is64=(magic==0x20b)
    opt=pe+24
    entry=u32(b,opt+16)
    ndir = u32(b, opt+(108 if is64 else 92))
    dirbase = opt+(112 if is64 else 96)
    tls = dirbase+9*8
    tls_va=u32(b,tls); tls_sz=u32(b,tls+4)
    print(f"machine={'x64' if machine==0x8664 else 'x86' if machine==0x14c else hex(machine)} "
          f"entryRVA={entry:#x} sections={nsec} TLS={'yes' if tls_va else 'no'}")
    sh=opt+optsz
    FL=[(0x20,'CODE'),(0x40,'IDATA'),(0x20000000,'EXEC'),(0x40000000,'READ'),(0x80000000,'WRITE')]
    for i in range(nsec):
        o=sh+i*40
        name=b[o:o+8].split(b'\0')[0].decode('latin1')
        vsz=u32(b,o+8); rsz=u32(b,o+16); ch=u32(b,o+36)
        fl='|'.join(n for m,n in FL if ch&m)
        print(f"  {name:<8} vsz={vsz:#010x} rsz={rsz:#010x} {fl}")
if __name__=='__main__':
    main(sys.argv[1])
