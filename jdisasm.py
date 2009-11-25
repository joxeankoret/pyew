#! /usr/bin/python2.4
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or   
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the  
# GNU General Public License for more details.

"""jdisasm.py: a Java .class file disassembler

by pts@fazekas.hu at Sun Apr 26 20:36:26 CEST 2009

jdisasm can display a Java .class file in a human readable form, showing the
class name, the field names and types, the method names, types and codes
(including instruction memonics). For each item shown, the file offset is
prepended. (Neither javap or jad can display the file offset.)

jdisasm is based on the documentation
http://java.sun.com/docs/books/jvms/second_edition/html/ClassFile.doc.html
"""

__author__ = 'pts@fazekas.hu'

import struct
import sys


ACCH = {
    'PUBLIC':  0x1,
    'PRIVATE': 0x2,
    'PROTECTED': 0x4,
    'STATIC': 0x8,
    'FINAL': 0x10,
    'SYNCHRONIZED': 0x20,  # same as ACC_SUPER
    'VOLATILE': 0x40,
    'TRANSIENT': 0x80,
    'NATIVE': 0x100,
    'ABSTRACT': 0x400,
    'STRICT': 0x800,
}


TAG_TO_CONSTANT_TYPE = {
    7: 'Class_info',
    9: 'Fieldref',
    10: 'Methodref',
    11: 'InterfaceMethodref',
    8: 'String',
    3: 'Integer',
    4: 'Float',
    5: 'Long',
    6: 'Double',
    12: 'NameAndType',
    1: 'Utf8',
}


INSTRUCTIONS = {
    50: ('aaload', 1),
    83: ('aastore', 1),
    1: ('aconst_null', 1),
    25: ('aload', 2),
    42: ('aload_0', 1),
    43: ('aload_1', 1),
    44: ('aload_2', 1),
    45: ('aload_3', 1),
    189: ('anewarray', 3),
    176: ('areturn', 1),
    176: ('areturn', 1),
    190: ('arraylength', 1),
    190: ('arraylength', 1),
    58: ('astore', 2),
    75: ('astore_0', 1),
    76: ('astore_1', 1),
    77: ('astore_2', 1),
    78: ('astore_3', 1),
    191: ('athrow', 1),
    51: ('baload', 1),
    84: ('bastore', 1),
    16: ('bipush', 2),
    52: ('caload', 1),
    85: ('castore', 1),
    192: ('checkcast', 3),
    144: ('d2f', 1),
    142: ('d2i', 1),
    143: ('d2l', 1),
    99: ('dadd', 1),
    49: ('daload', 1),
    82: ('dastore', 1),
    152: ('dcmpg', 1),
    151: ('dcmpl', 1),
    14: ('dconst_0', 1),
    14: ('dconst_0', 1),
    111: ('ddiv', 1),
    24: ('dload', 2),
    24: ('dload', 2),
    38: ('dload_0', 1),
    39: ('dload_1', 1),
    40: ('dload_2', 1),
    41: ('dload_3', 1),
    107: ('dmul', 1),
    119: ('dneg', 1),
    115: ('drem', 1),
    175: ('dreturn', 1),
    57: ('dstore', 2),
    71: ('dstore_0', 1),
    72: ('dstore_1', 1),
    73: ('dstore_2', 1),
    74: ('dstore_3', 1),
    103: ('dsub', 1),
    89: ('dup', 1),
    90: ('dup_x1', 1),
    91: ('dup_x2', 1),
    92: ('dup2', 1),
    93: ('dup2_x1', 1),
    141: ('f2d', 1),
    139: ('f2i', 1),
    140: ('f2l', 1),
    98: ('fadd', 1),
    48: ('faload', 1),
    81: ('fastore', 1),
    150: ('fcmpg', 1),
    149: ('fcmpl', 1),
    11: ('fconst_0', 1),
    12: ('fconst_1', 1),
    13: ('fconst_2', 1),
    110: ('fdiv', 1),
    23: ('fload', 2),
    34: ('fload_0', 1),
    35: ('fload_1', 1),
    36: ('fload_2', 1),
    37: ('fload_3', 1),
    106: ('fmul', 1),
    118: ('fneg', 1),
    114: ('frem', 1),
    174: ('freturn', 1),
    56: ('fstore', 2),
    67: ('fstore_0', 1),
    68: ('fstore_1', 1),
    69: ('fstore_2', 1),
    70: ('fstore_3', 1),
    102: ('fsub', 1),
    180: ('getfield', 3),
    178: ('getstatic', 3),
    167: ('goto', 3),
    200: ('goto_w', 5),
    145: ('i2b', 1),
    146: ('i2c', 1),
    135: ('i2d', 1),
    134: ('i2f', 1),
    133: ('i2l', 1),
    147: ('i2s', 1),
    96: ('iadd', 1),
    46: ('iaload', 1),
    126: ('iand', 1),
    79: ('iastore', 1),
    2: ('iconst_m1', 1),
    3: ('iconst_0', 1),
    4: ('iconst_1', 1),
    5: ('iconst_2', 1),
    6: ('iconst_3', 1),
    7: ('iconst_4', 1),
    8: ('iconst_5', 1),
    108: ('idiv', 1),
    165: ('if_acmpeq', 3),
    166: ('if_acmpne', 3),
    159: ('if_icmpeq', 3),
    160: ('if_icmpne', 3),
    161: ('if_icmplt', 3),
    162: ('if_icmpge', 3),
    163: ('if_icmpgt', 3),
    164: ('if_icmple', 3),
    153: ('ifeq', 3),
    154: ('ifne', 3),
    155: ('iflt', 3),
    156: ('iffe', 3),
    157: ('ifgt', 3),
    158: ('ifle', 3),
    199: ('ifnonnull', 3),
    198: ('ifnull', 3),
    132: ('iinc', 3),
    21: ('iload', 2),
    26: ('iload_0', 1),
    27: ('iload_1', 1),
    28: ('iload_2', 1),
    29: ('iload_3', 1),
    104: ('imul', 1),
    116: ('ineg', 1),
    193: ('instanceof', 3),
    185: ('invokeinterface', 5),
    183: ('invokespecial', 3),
    184: ('invokestatic', 3),
    182: ('invokevirtual', 3),
    128: ('ior', 1),
    112: ('irem', 1),
    172: ('ireturn', 1),
    120: ('ishl', 1),
    122: ('ishr', 1),
    54: ('istore', 2),
    59: ('istore_0', 1),
    60: ('istore_1', 1),
    61: ('istore_2', 1),
    62: ('istore_3', 1),
    100: ('isub', 1),
    124: ('iushr', 1),
    130: ('ixor', 1),
    168: ('jsr', 3),
    201: ('jsr_w', 5),
    138: ('l2d', 1),
    137: ('l2f', 1),
    136: ('l2i', 1),
    97: ('ladd', 1),
    47: ('laload', 1),
    127: ('land', 1),
    80: ('lastore', 1),
    2: ('lconst_m1', 1),
    3: ('lconst_0', 1),
    4: ('lconst_1', 1),
    5: ('lconst_2', 1),
    6: ('lconst_3', 1),
    7: ('lconst_4', 1),
    8: ('lconst_5', 1),
    148: ('lcmp', 1),
    9: ('lconst_0', 1),
    10: ('lconst_1', 1),
    18: ('ldc', 2),
    19: ('ldc_w', 3),
    20: ('ldc2_w', 3),
    109: ('ldiv', 1),
    22: ('lload', 2),
    30: ('lload_0', 1),
    31: ('lload_1', 1),
    32: ('lload_2', 1),
    33: ('lload_3', 1),
    105: ('lmul', 1),
    117: ('lneg', 1),
    171: ('lookupswitch', None),  # variable length
    129: ('lor', 1),
    113: ('lrem', 1),
    173: ('lreturn', 1),
    121: ('lshl', 1),
    123: ('lshr', 1),
    55: ('lstore', 2),
    63: ('lstore_0', 1),
    64: ('lstore_1', 1),
    65: ('lstore_2', 1),
    66: ('lstore_3', 1),
    101: ('lsub', 1),
    125: ('lushr', 1),
    131: ('lxor', 1),
    194: ('monitorenter', 1),
    195: ('monitorexit', 1),
    197: ('multianewarray', 4),
    187: ('new', 3),
    188: ('newarray', 2),
    0: ('nop', 1),
    87: ('pop', 1),
    88: ('pop2', 1),
    181: ('putfield', 3),
    179: ('putstatic', 3),
    169: ('ret', 2),
    177: ('return', 1),
    53: ('saload', 1),
    86: ('sastore', 1),
    17: ('sipush', 3),
    95: ('swap', 1),
    170: ('tableswitch', None),  # variable length
    196: ('wide', None),  # variable length, 6 for iinc=132, 4 otherwise
    254: ('impdep1', 1),
    255: ('impdep2', 1),
    202: ('breakpoint', 1),
}
"""Maps an opcode to a (mnemonic, ilength) list.

ilength is the instruction size in bytes, including the opcode.
"""


def FormatAccessFlags(acc, is_class=False):
  if not isinstance(acc, int):
    raise TypeError
  items = []
  for name in sorted(ACCH):
    if acc & ACCH[name]:
      if is_class and name == 'SYNCHRONIZED':
        items.append('ACC_SUPER')
      else:
        items.append('ACC_' + name)
      acc &= ~ACCH[name]
  if acc:
    items.append('0x%x' % acc)
  if not items:
    items.append(0)
  return '|'.join(items)


def DumpCode(s, i, iend, constant_class, constant_utf8,
             constant_name_and_type, constant_method_ref,
             constant_interface_method_ref):
  max_stack, = struct.unpack('>H', s[i : i + 2])
  print '0x%08x max_stack=%d' % (i, max_stack)
  i += 2

  max_locals, = struct.unpack('>H', s[i : i + 2])
  print '0x%08x max_locals=%d' % (i, max_locals)
  i += 2

  code_length, = struct.unpack('>L', s[i : i + 4])
  i += 4
  code_ofs = i
  print '0x%08x code:' % i
  j = i
  i += code_length
  while j < i:
    opcode = ord(s[j])
    mnemonic, ilength = INSTRUCTIONS[opcode]
    if opcode == 185:  # invokeinterface
      j0 = j
      j += 1
      interface_method_ref_index, count = struct.unpack('>HB', s[j : j + 3])
      j += 4
      class_index, name_and_type_index = constant_interface_method_ref[
          interface_method_ref_index]
      name_index, descriptor_index = constant_name_and_type[
          name_and_type_index]
      print '0x%08x %s %r %r %r %d' % (
          j0, mnemonic, constant_utf8[constant_class[class_index]],
          constant_utf8[name_index], constant_utf8[descriptor_index],
          count)
    elif opcode in (184, 183, 182):
      # invokestatic, invokespecial, invokevirtual
      j0 = j
      j += 1
      method_ref_index, = struct.unpack('>H', s[j : j + 2])
      j += 2
      class_index, name_and_type_index = constant_method_ref[method_ref_index]
      name_index, descriptor_index = constant_name_and_type[
          name_and_type_index]
      print '0x%08x %s %r %r %r' % (
          j0, mnemonic, constant_utf8[constant_class[class_index]],
          constant_utf8[name_index], constant_utf8[descriptor_index])
    elif ilength:
      if ilength > 1:
        # TODO(pts): Print the arguments propely, using the constant_pool.
        print '0x%08x %s %r' % (j, mnemonic, s[j + 1 : j + ilength])
      else:
        print '0x%08x %s' % (j, mnemonic)
      j += ilength
    elif opcode == 171:  # lookupswitch
      # TODO(pts): test this
      j0 = j
      j += 1
      while (j - code_ofs) & 3:
        j += 1
      default, = struct.unpack('>L', s[j : j + 4])
      j += 4
      npairs, = struct.unpack('>L', s[j : j + 4])
      j += 4
      print '0x%08x lookupswitch default=%d pairs=%r' % (
          j0, default,
          struct.unpack('>%dl' % (npairs << 1), s[j : j + (npairs << 3)]))
      j += npairs << 3
    elif opcode == 170:  # tableswitch
      # TODO(pts): test this
      j0 = j
      j += 1
      while (j - code_ofs) & 3:
        j += 1
      low, = struct.unpack('>L', s[j : j + 4])
      j += 4
      high, = struct.unpack('>L', s[j : j + 4])
      j += 4
      noffsets = high - low + 1
      print '0x%08x tableswitch low=%d high=%d offsets=%r' % (
          j0, low, high,
          struct.unpack('>%dl' % noffsets, s[j : j + (noffsets << 2)]))
      j += noffsets << 2
    elif opcode == 196:  # wide
      # TODO(pts): test this
      subopcode = ord(s[j + 1])
      if subopcode == 132:  # iinc
        ilength = 6
      else:
        ilength = 4
      submnemonic = INSTRUCTIONS[subopcode][1]
      print '0x%08x wide %s %r' % (j, submnemonic, s[j + 2 : j + ilength])
      j += ilength
    else:
      assert 0, 'unknown length for opcode %d' % opcode
  assert i == j, 'code parse error got=%d expected=%d' % (j, i)
  print '0x%08x end-of-code' % i

  exception_table_length, = struct.unpack('>H', s[i : i + 2])
  print '0x%08x exception_table_length=%d' % (i, exception_table_length)
  i += 2

  for ei in xrange(exception_table_length):
    ei_start_pc, = struct.unpack('>H', s[i : i + 2])
    print '0x%08x exception_table[%d].start_pc=%d' % (
        i, ei, ei_start_pc)
    i += 2

    ei_end_pc, = struct.unpack('>H', s[i : i + 2])
    print '0x%08x exception_table[%d].end_pc=%d' % (
        i, ei, ei_end_pc)
    i += 2

    ei_handler_pc, = struct.unpack('>H', s[i : i + 2])
    print '0x%08x exception_table[%d].handler_pc=%d' % (
        i, ei, ei_end_pc)
    i += 2

    ei_catch_type, = struct.unpack('>H', s[i : i + 2])
    print '0x%08x exception_table[%d].catch_type=%d' % (
        i, ei, ei_catch_type)
    i += 2

  attributes_count, = struct.unpack('>H', s[i : i + 2])
  print '0x%08x attributes_count=%d' % (i, attributes_count)
  i += 2

  for ai in xrange(attributes_count):
    ai_name_index, = struct.unpack('>H', s[i : i + 2])
    print '0x%08x attribute[%d].name=%r' % (
        i, ai, constant_utf8[ai_name_index])
    i += 2
    assert constant_utf8[ai_name_index] != 'Code'

    ai_attribute_length, = struct.unpack('>L', s[i : i + 4])
    i += 4
    ai_info = s[i : i + ai_attribute_length]
    print '0x%08x attribute[%d].info=%r' % (
        i, ai, ai_info)
    i += ai_attribute_length
    # TODO(pts): Parse the attribute.

  assert i == iend, 'end-of-code-attr expected at %d, len=%d' % (i, iend)
  print '0x%08x end-of-code-attr' % i


def ParseClass(file_name, max_lines=0, offset=0):
  try:
    f = open(file_name)
    s = f.read()
  finally:
    f.close()

  i = 0

  magic, = struct.unpack('>L', s[i : i + 4])
  print '0x%08x magic=0x%08x' % (i, magic)
  assert magic == 0xcafebabe
  i += 4

  major_version, = struct.unpack('>H', s[i : i + 2])
  print '0x%08x major_version=%d' % (i, major_version)
  i += 2

  minor_version, = struct.unpack('>H', s[i : i + 2])
  print '0x%08x minor_version=%d' % (i, minor_version)
  i += 2

  constant_pool_count, = struct.unpack('>H', s[i : i + 2])
  print '0x%08x constant_pool_count=%d' % (i, constant_pool_count)
  i += 2

  # Maps a CONSTANT_Class_info index to a name_index
  constant_class = {}
  # Maps a CONSTANT_Utf8 index to a string
  constant_utf8 = {}
  # Maps a CONSTANT_NameAndType index to (name_index, descriptor_index)
  constant_name_and_type = {}
  # Maps a CONSTANT_Methodref index to (class_index, name_and_type_index)
  constant_method_ref = {}
  # Maps a CONSTANT_InterfaceMethodref index to
  # (class_index, name_and_type_index)
  constant_interface_method_ref = {}
  
  # Maps a name to its CONSTANT_utf8 index 
  name_to_constant_idx = {}
  ci = 1
  while ci < constant_pool_count:
    tag = ord(s[i])
    print '0x%08x constant %d tag=%s' % (
        i, ci, TAG_TO_CONSTANT_TYPE.get(tag, tag)),
    assert tag in TAG_TO_CONSTANT_TYPE
    if tag == 7:  #CONSTANT_Class_info
      i += 1
      j, = struct.unpack('>H', s[i : i + 2])
      constant_class[ci] = j
      print j,
      i += 2
    elif tag == 9:  #CONSTANT_Fieldref
      i += 5
    elif tag == 10:  #CONSTANT_Methodref
      i += 1
      constant_method_ref[ci] = struct.unpack('>HH', s[i : i + 4])
      print constant_method_ref[ci][0], constant_method_ref[ci][1],
      i += 4
    elif tag == 11:  #CONSTANT_InterfaceMethodref
      i += 1
      constant_interface_method_ref[ci] = struct.unpack('>HH', s[i : i + 4])
      print constant_interface_method_ref[ci][0],
      print constant_interface_method_ref[ci][1],
      i += 4
    elif tag == 8:  #CONSTANT_String
      i += 3
    elif tag == 3:  #CONSTANT_Integer
      i += 5
    elif tag == 4:  #CONSTANT_Float
      i += 5
    elif tag == 5:  #CONSTANT_Long
      i += 9
      ci += 1
    elif tag == 6:  #CONSTANT_Double
      i += 9
      ci += 1
    elif tag == 12:  #CONSTANT_NameAndType
      i += 1
      constant_name_and_type[ci] = struct.unpack('>HH', s[i : i + 4])
      print constant_name_and_type[ci][0], constant_name_and_type[ci][1],
      i += 4
    elif tag == 1:  #CONSTANT_Utf8
      blen = struct.unpack('>H', s[i + 1 : i + 3])[0]
      name = s[i + 3 : i + 3 + blen]
      name_to_constant_idx[name] = ci
      constant_utf8[ci] = name
      print repr(name),
      i += 3 + blen
    else:
      assert 0
    print
    ci += 1

  access_flags, = struct.unpack('>H', s[i : i + 2])
  print '0x%08x access_flags=%s' % (
      i, FormatAccessFlags(access_flags, is_class=True))
  i += 2

  this_class, = struct.unpack('>H', s[i : i + 2])
  print '0x%08x this_class=%r' % (
      i, constant_utf8[constant_class[this_class]])
  i += 2

  super_class, = struct.unpack('>H', s[i : i + 2])
  print '0x%08x super_class=%r' % (
      i, constant_utf8[constant_class[super_class]])
  i += 2

  interfaces_count, = struct.unpack('>H', s[i : i + 2])
  print '0x%08x interfaces_count=%d' % (i, interfaces_count)
  i += 2

  for ii in xrange(interfaces_count):
    interface, = struct.unpack('>H', s[i : i + 2])
    print '0x%08x interface[%d]=%r' % (
        i, ii, constant_utf8[constant_class[interface]])
    i += 2

  fields_count, = struct.unpack('>H', s[i : i + 2])
  print '0x%08x fields_count=%d' % (i, fields_count)
  i += 2

  for fi in xrange(fields_count):
    fi_access_flags, = struct.unpack('>H', s[i : i + 2])
    print '0x%08x field[%d].access_flags=%s' % (
        i, fi, FormatAccessFlags(fi_access_flags))
    i += 2

    fi_name_index, = struct.unpack('>H', s[i : i + 2])
    print '0x%08x field[%d].name=%r' % (
        i, fi, constant_utf8[fi_name_index])
    i += 2

    fi_descriptor_index, = struct.unpack('>H', s[i : i + 2])
    print '0x%08x field[%d].descriptor=%r' % (
        i, fi, constant_utf8[fi_descriptor_index])
    i += 2

    fi_attributes_count, = struct.unpack('>H', s[i : i + 2])
    print '0x%08x field[%d].attributes_count=%d' % (i, fi, fi_attributes_count)
    i += 2

    for ai in xrange(fi_attributes_count):
      ai_name_index, = struct.unpack('>H', s[i : i + 2])
      print '0x%08x field[%d].attribute[%d].name=%r' % (
          i, fi, ai, constant_utf8[ai_name_index])
      i += 2
      assert constant_utf8[ai_name_index] != 'Code'

      ai_attribute_length, = struct.unpack('>L', s[i : i + 4])
      i += 4
      ai_info = s[i : i + ai_attribute_length]
      print '0x%08x field[%d].attribute[%d].info=%r' % (
          i, fi, ai, ai_info)
      i += ai_attribute_length
      # TODO(pts): Parse the attribute.

  methods_count, = struct.unpack('>H', s[i : i + 2])
  print '0x%08x methods_count=%d' % (i, methods_count)
  i += 2

  for fi in xrange(methods_count):
    fi_access_flags, = struct.unpack('>H', s[i : i + 2])
    print '0x%08x method[%d].access_flags=%s' % (
        i, fi, FormatAccessFlags(fi_access_flags))
    i += 2

    fi_name_index, = struct.unpack('>H', s[i : i + 2])
    print '0x%08x method[%d].name=%r' % (
        i, fi, constant_utf8[fi_name_index])
    i += 2

    fi_descriptor_index, = struct.unpack('>H', s[i : i + 2])
    print '0x%08x method[%d].descriptor=%r' % (
        i, fi, constant_utf8[fi_descriptor_index])
    i += 2

    fi_attributes_count, = struct.unpack('>H', s[i : i + 2])
    print '0x%08x method[%d].attributes_count=%d' % (i, fi, fi_attributes_count)
    i += 2

    for ai in xrange(fi_attributes_count):
      ai_name_index, = struct.unpack('>H', s[i : i + 2])
      print '0x%08x method[%d].attribute[%d].name=%r' % (
          i, fi, ai, constant_utf8[ai_name_index])
      i += 2

      ai_attribute_length, = struct.unpack('>L', s[i : i + 4])
      i += 4
      if constant_utf8[ai_name_index] == 'Code':
        print '0x%08x method[%d].attribute[%d].code:' % (i, fi, ai)
        # TODO(pts): limit s[:ai_info...]
        DumpCode(
            s, i, i + ai_attribute_length,
            constant_class=constant_class, constant_utf8=constant_utf8,
            constant_name_and_type=constant_name_and_type,
            constant_method_ref=constant_method_ref,
            constant_interface_method_ref=constant_interface_method_ref)
      else:
        ai_info = s[i : i + ai_attribute_length]
        print '0x%08x method[%d].attribute[%d].info=%r' % (
            i, fi, ai, ai_info)
      i += ai_attribute_length
      # TODO(pts): Parse the attribute.

  attributes_count, = struct.unpack('>H', s[i : i + 2])
  print '0x%08x attributes_count=%d' % (i, attributes_count)
  i += 2

  for ai in xrange(attributes_count):
    ai_name_index, = struct.unpack('>H', s[i : i + 2])
    print '0x%08x attribute[%d].name=%r' % (
        i, ai, constant_utf8[ai_name_index])
    i += 2
    assert constant_utf8[ai_name_index] != 'Code'

    ai_attribute_length, = struct.unpack('>L', s[i : i + 4])
    i += 4
    ai_info = s[i : i + ai_attribute_length]
    print '0x%08x attribute[%d].info=%r' % (
        i, ai, ai_info)
    i += ai_attribute_length
    # TODO(pts): Parse the attribute.

  assert i == len(s), 'class EOF expected at %d, len=%d' % (i, len(s))
  print '0x%08x EOF' % i

  return name_to_constant_idx


if __name__ == '__main__':
  if len(sys.argv) != 2:
    print >>sys.stderr, 'Usage: %s <file.class>' % sys.argv[0]
    sys.exit(1)
  ParseClass(file_name=sys.argv[1])
