#!/usr/bin/python
__author__ = 'srodgers'

import struct
import argparse
import ConfigParser



# First byte of the application image
ESP_IMAGE_MAGIC = 0xe9

# Initial state for the checksum routine
ESP_CHECKSUM_MAGIC = 0xef

SIGNATURE = "ESP8266HWSTARSR"

class ESPFirmwareImage:

    """ read the patch file from disk """
    def __init__(self, filename = None):
        self.segments = []
        self.entrypoint = 0
        self.flash_mode = 0
        self.flash_size_freq = 0
        self.patchelem = 0
        self.patchrecordlength = 0
        self.patchbase = 0
        self.patchdata = None


        if filename is not None:
            f = file(filename, 'rb')
            (magic, segments, self.flash_mode, self.flash_size_freq, self.entrypoint) = struct.unpack('<BBBBI', f.read(8))

            # some sanity check
            if magic != ESP_IMAGE_MAGIC or segments > 16:
                raise Exception('Invalid firmware image')

            for i in xrange(segments):
                (offset, size) = struct.unpack('<II', f.read(8))
                if offset > 0x40200000 or offset < 0x3ffe0000 or size > 65536:
                    raise Exception('Suspicious segment %x,%d' % (offset, size))
                self.segments.append((offset, size, bytearray(f.read(size))))

            # Skip the padding. The checksum is stored in the last byte so that the
            # file is a multiple of 16 bytes.
            align = 15-(f.tell() % 16)
            f.seek(align, 1)

            self.checksum = ord(f.read(1))
            #print "Read Checksum: {}".format(self.checksum)

    """ Calculate checksum of a blob, as it is defined by the ROM """
    @staticmethod
    def calcchecksum(data, state = ESP_CHECKSUM_MAGIC):
        for b in data:
            state ^= b
        return state

    """ find the patch area in memory and make a note of its location """
    def _findPatchArea(self):
        for(offset, size, data) in self.segments:
            #print ("offset = {} size = {}".format( hex(offset), hex(size)))
            for base in xrange(size):
                if str(data[base:base + len(SIGNATURE)]) == SIGNATURE:
                    #print("Signature found at base: {}!".format(base))
                    self.patchdata = data
                    self.patchbase = base
                    (sig, magic, self.patchelem, self.patchrecordlength) = struct.unpack('<16sIBB', data[base:base + 22])
                    return
        raise Exception("Signature: {} not found!".format(SIGNATURE))

    """ return a list of a list of patch items """
    def getPatchItems(self):
            self._findPatchArea()
            patchitems = []
            for i in xrange(self.patchelem):
                entrybase = (self.patchrecordlength * i) + self.patchbase + 32;
                formatstring = "<B15s{}s".format(self.patchrecordlength - 16)
                (imgflags, imgkey, imgvalue) = \
                struct.unpack(formatstring, self.patchdata[entrybase:entrybase + self.patchrecordlength])
                # Terminate loop if nul character seen in first key byte
                if not ord(imgkey[0:1]):
                    return patchitems
                imgkey = imgkey.rstrip("\0")
                imgvalue = imgvalue.rstrip("\0")
                #print("Entrybase: {} Flags: {} Key: {} Value: {}".format(entrybase, hex(imgflags), imgkey, imgvalue))
                patchitems.append([imgflags, imgkey, imgvalue])
            return patchitems

    """ clear out the old patch items and replace them with the list of a list passed in """
    def setPatchItems(self, newpatchitems):
            self._findPatchArea()
            entrybase = self.patchbase + 32
            # Zero out all records
            for i in xrange(self.patchrecordlength * self.patchelem):
                self.patchdata[entrybase + i] = 0
            # Update patch area
            for i in xrange(len(newpatchitems)):
                formatstring = "<B15s{}s".format(self.patchrecordlength - 16)
                self.patchdata[entrybase + i * self.patchrecordlength: entrybase + (i + 1) * self.patchrecordlength] = \
                struct.pack(formatstring, newpatchitems[i][0], newpatchitems[i][1], newpatchitems[i][2])
                #print newpatchitems[i][1]
            return

    """ save the patch file to disk """
    def save(self, filename):
        f = file(filename, 'wb')
        f.write(struct.pack('<BBBBI', ESP_IMAGE_MAGIC, len(self.segments),
            self.flash_mode, self.flash_size_freq, self.entrypoint))

        checksum = ESP_CHECKSUM_MAGIC
        for (offset, size, data) in self.segments:
            f.write(struct.pack('<II', offset, size))
            f.write(data)
            checksum = self.calcchecksum(data, checksum)

        align = 15-(f.tell() % 16)
        f.seek(align, 1)
        f.write(struct.pack('B', checksum))
        #print "Write Checksum: {}".format(checksum)

if __name__ == '__main__':
    #command line parser setup
    parser = argparse.ArgumentParser(description = 'ESP8266 Config Patching Utility', prog = 'espcfgpatcher.py')

    subparsers = parser.add_subparsers(dest = 'operation', help = 'Run espcfgpatcher.py {command} -h for additional help')

    parser_print_config = subparsers.add_parser('print_config', help = 'Print current configuration')
    parser_print_config.add_argument('infile', help = 'Input firmware image file name')

    parser_patch = subparsers.add_parser('patch', help = 'Patch firmware file')
    parser_patch.add_argument('infile', help = 'Input firmware image file name')
    parser_patch.add_argument('configfile', help = 'Configuration file name')
    parser_patch.add_argument('outfile', help = 'Output firmware image file name')

    # parse the args and die on error
    args = parser.parse_args()

    # always load the image
    Img = ESPFirmwareImage(args.infile)
    patchItems = Img.getPatchItems()

    # if patch, read the patch file and make the changes
    if(args.operation == "patch"):
        Config = ConfigParser.ConfigParser()
        Config.read(args.configfile)
        configdict = dict(Config.items("general"))
        for i in xrange(len(patchItems)):
            if (patchItems[i][1].lower() not in configdict):
                if(patchItems[i][0] & 1):
                    raise Exception("Required key {} not found in config file!".format(patchItems[i][1]))
            else:
                patchItems[i][2] = configdict[patchItems[i][1].lower()]
        Img.setPatchItems(patchItems)
    # otherwise just list the changes in the current input file
    else:
        print"{0:8} {1:15} {2:64}".format("FLAGS", "KEY", "VALUE")
        print"{0:8} {1:15} {2:64}".format("-----", "---", "-----")
        for i in xrange(len(patchItems)):
            print"{0:<8} {1:15} {2:64}".format(hex(patchItems[i][0]), patchItems[i][1], patchItems[i][2])
    if(args.operation == "patch"):
        Img.save(args.outfile)
