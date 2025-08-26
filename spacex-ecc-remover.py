

def read_dump(file: str) -> bytes:
    with open(file, "rb") as f:
        dump = f.read()
    return dump


def write_dump(file: str, dump: bytes) -> None:
    with open(file, "wb") as f:
        f.write(dump)


"""
~/Documents/binwalk/target/release/binwalk linux_no_ecc

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
DECIMAL                            HEXADECIMAL                        DESCRIPTION
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
1                                  0x1                                LZMA compressed data, properties: 0x5D, dictionary size: 67108864 bytes, compressed size: 3908854 bytes, uncompressed size: -1 bytes
3909033                            0x3BA5A9                           Device tree blob (DTB), version: 17, CPU ID: 0, total size: 59345 bytes
3968521                            0x3C8E09                           Device tree blob (DTB), version: 17, CPU ID: 0, total size: 57633 bytes
4026293                            0x3D6FB5                           Device tree blob (DTB), version: 17, CPU ID: 0, total size: 59303 bytes
4085733                            0x3E57E5                           Device tree blob (DTB), version: 17, CPU ID: 0, total size: 57661 bytes
4143553                            0x3F39C1                           Device tree blob (DTB), version: 17, CPU ID: 0, total size: 59695 bytes
4203405                            0x40238D                           Device tree blob (DTB), version: 17, CPU ID: 0, total size: 59728 bytes
4263289                            0x410D79                           Device tree blob (DTB), version: 17, CPU ID: 0, total size: 59750 bytes
4323193                            0x41F779                           Device tree blob (DTB), version: 17, CPU ID: 0, total size: 59750 bytes
4383109                            0x42E185                           Device tree blob (DTB), version: 17, CPU ID: 0, total size: 59750 bytes
4443017                            0x43CB89                           Device tree blob (DTB), version: 17, CPU ID: 0, total size: 59750 bytes
4502921                            0x44B589                           Device tree blob (DTB), version: 17, CPU ID: 0, total size: 59890 bytes
4562965                            0x45A015                           Device tree blob (DTB), version: 17, CPU ID: 0, total size: 59928 bytes
4623045                            0x468AC5                           Device tree blob (DTB), version: 17, CPU ID: 0, total size: 59749 bytes
4682949                            0x4774C5                           Device tree blob (DTB), version: 17, CPU ID: 0, total size: 59749 bytes
4742853                            0x485EC5                           Device tree blob (DTB), version: 17, CPU ID: 0, total size: 58037 bytes
4801045                            0x494215                           Device tree blob (DTB), version: 17, CPU ID: 0, total size: 57603 bytes
4858801                            0x4A23B1                           Device tree blob (DTB), version: 17, CPU ID: 0, total size: 57857 bytes
4916813                            0x4B064D                           Device tree blob (DTB), version: 17, CPU ID: 0, total size: 57857 bytes
4974825                            0x4BE8E9                           Device tree blob (DTB), version: 17, CPU ID: 0, total size: 57798 bytes
5032773                            0x4CCB45                           Device tree blob (DTB), version: 17, CPU ID: 0, total size: 58164 bytes
5091085                            0x4DAF0D                           Device tree blob (DTB), version: 17, CPU ID: 0, total size: 58798 bytes
5150049                            0x4E9561                           Device tree blob (DTB), version: 17, CPU ID: 0, total size: 59704 bytes
5209925                            0x4F7F45                           Device tree blob (DTB), version: 17, CPU ID: 0, total size: 57972 bytes
5268061                            0x50625D                           Device tree blob (DTB), version: 17, CPU ID: 0, total size: 60365 bytes
5328601                            0x514ED9                           Device tree blob (DTB), version: 17, CPU ID: 0, total size: 58633 bytes
5387453                            0x5234BD                           LZMA compressed data, properties: 0x5D, dictionary size: 67108864 bytes, compressed size: 8182573 bytes, uncompressed size: -1 bytes
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

"""


def ecc_remover(start: int, dump: bytes) -> bytes:
    MAGIC       = b"SXECCv1"
    CW          = 255
    DATA_BYTES  = 222
    MARKER_OFF  = DATA_BYTES

    out  = bytearray()
    pos  = start
    end  = len(dump)

    while True :
        hdr = dump.find(MAGIC, pos)
        if hdr < 0:
            break

        ptr = hdr + CW
        seg = bytearray()

        while True:
            cw = dump[ptr:ptr+CW]
            marker = cw[MARKER_OFF]
            seg.extend(cw[:DATA_BYTES])
            #seg.extend(cw[:DATA])
            ptr += CW

            if marker == ord('$'):
                break
            if marker != ord('*'):
                print("Invalid marker!")
                break


        if ptr + CW > end or dump[ptr] != ord('!'):
            print("error ...")
            break

        footer_stub = dump[ptr:ptr + CW]
        paylen  = int.from_bytes(footer_stub[1:5], "big")
        if paylen < len(seg):
            seg = seg[:paylen]
        ptr += CW                                
        out.extend(seg)                    
        pos = ptr                                

    return bytes(out)


def main(dump_file: str, output_file: str) -> None:
    dump = read_dump(dump_file)
    print(f"Removing ecc")
    start = 0x0
    dump_without_ecc = ecc_remover(start, dump)
    print(f"Writing result to file: '{output_file}' ...")
    write_dump(output_file, dump_without_ecc)
    print(f"Write complete!")


if __name__ == "__main__":
    main("linux_with_ecc", "linux_no_ecc")
