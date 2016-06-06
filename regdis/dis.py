import ctypes
from itertools import islice
import pprint
import re
import sre_constants

HAVE_ARG = {
    sre_constants.MARK,
    sre_constants.GROUPREF,
    sre_constants.GROUPREF_IGNORE,
}
HAVE_LITERAL_ARG = {
    sre_constants.LITERAL,
    sre_constants.NOT_LITERAL,
    sre_constants.LITERAL_IGNORE,
    sre_constants.NOT_LITERAL_IGNORE,
}
NO_ARG = {
    sre_constants.SUCCESS,
    sre_constants.FAILURE,
    sre_constants.ANY,
    sre_constants.ANY_ALL,
}
SIZEOF_SRE_CODE = 4
SRE_CODE_BITS = 8 * SIZEOF_SRE_CODE


class InvalidCodeError(Exception):
    pass


def get_code(pattern, unsafe=False):
    """Returns the code for this regex pattern.

    If unsafe is False, either uses the __pattern_code__ attribute or raises an error. If it is
    True, falls back to using ctypes to either produce the code or die a horrible death.

    """
    if isinstance(pattern, str):
        pattern = re.compile(pattern)
    try:
        return pattern.__pattern_code__
    except AttributeError:
        if not unsafe:
            raise NotImplementedError(
                'regdis requires a Python version that exposes __pattern_code__')
        int_ptr = ctypes.POINTER(ctypes.c_uint32)
        offset = (
            0
            # _PyObject_HEAD_EXTRA, probably only in debug builds
            + 2 * ctypes.sizeof(int_ptr)
            + ctypes.sizeof(ctypes.c_long)  # ob_refcnt
            + ctypes.sizeof(int_ptr)  # ob_type
            + ctypes.sizeof(ctypes.c_long)  # ob_size
            + ctypes.sizeof(ctypes.c_long)  # groups
            + ctypes.sizeof(int_ptr)  # groupindex
            + ctypes.sizeof(int_ptr)  # indexgroup
            + ctypes.sizeof(int_ptr)  # pattern
            # actually an int but alignment
            + ctypes.sizeof(ctypes.c_long)  # flags
            + ctypes.sizeof(int_ptr)  # weakreflist
            # same here
            + ctypes.sizeof(ctypes.c_long)  # isbytes
        )
        pattern_address = id(pattern)
        code_size = ctypes.c_long.from_address(pattern_address + offset).value
        code_start = pattern_address + offset + ctypes.sizeof(ctypes.c_long)
        code = []
        for i in range(code_size):
            address = code_start + i * ctypes.sizeof(ctypes.c_uint32)
            code.append(ctypes.c_uint32.from_address(address).value)
        return tuple(code)


def dis(pattern, unsafe=False):
    """Disassemble a pattern's instructions into a readable format."""
    pprint.pprint(list(get_instructions(pattern, unsafe=unsafe)))


def get_instructions(pattern, unsafe=False):
    """Generator of the instructions in a pattern."""
    # closely follows _validate_inner in _sre.c
    code = get_code(pattern, unsafe=unsafe)

    code_it = _CountingIterator(code)
    return _get_instructions_inner(code_it)


def _get_instructions_inner(code_it, max_pos=None):
    for codepoint in code_it:
        op = sre_constants.OPCODES[codepoint]
        if op in HAVE_ARG:
            arg = next(code_it)
            yield (op, arg)
        elif op in HAVE_LITERAL_ARG:
            arg = next(code_it)
            yield (op, chr(arg))
        elif op in NO_ARG:
            yield (op, None)
        elif op == sre_constants.AT:
            arg = next(code_it)
            yield (op, sre_constants.ATCODES[arg])
        elif op in (sre_constants.IN, sre_constants.IN_IGNORE):
            skip = next(code_it)
            charset = _consume_and_ensure_following(
                disassemble_charset, code_it, code_it.count + skip - 1, sre_constants.FAILURE)
            yield (op, (skip, charset))
        elif op == sre_constants.INFO:
            yield (op, _disassemble_info(code_it))
        elif op == sre_constants.BRANCH:
            yield (op, _disassemble_branch(code_it))
        elif op in (sre_constants.REPEAT_ONE, sre_constants.MIN_REPEAT_ONE):
            args = {}
            skip = args['skip'] = next(code_it)
            inner_max_pos = code_it.count + skip - 1
            args['min'] = next(code_it)
            args['max'] = next(code_it)
            if args['min'] > args['max'] or args['max'] > sre_constants.MAXREPEAT:
                raise InvalidCodeError('Invalid min or max value')
            args['inner'] = _consume_and_ensure_following(
                _get_instructions_inner, code_it, inner_max_pos, sre_constants.SUCCESS)
            _ensure_position(code_it, inner_max_pos)
            yield (op, args)
        elif op == sre_constants.REPEAT:
            args = {}
            skip = args['skip'] = next(code_it)
            inner_max_pos = code_it.count + skip - 1
            args['min'] = next(code_it)
            args['max'] = next(code_it)
            if args['min'] > args['max'] or args['max'] > sre_constants.MAXREPEAT:
                raise InvalidCodeError('Invalid min or max value')
            args['inner'] = list(_get_instructions_inner(code_it, max_pos=inner_max_pos))
            _ensure_position(code_it, inner_max_pos)
            next_op = sre_constants.OPCODES[next(code_it)]
            if next_op not in (sre_constants.MAX_UNTIL, sre_constants.MIN_UNTIL):
                raise InvalidCodeError('expected MAX_UNTIL or MIN_UNTIL to follow REPEAT')
            args['next_op'] = next_op
            yield (op, args)
        elif op == sre_constants.GROUPREF_EXISTS:
            starting_pos = code_it.count
            arg = next(code_it)
            skip = next(code_it)
            inner_max_pos = starting_pos + skip - 2

            args = {'arg': arg, 'skip': skip}

            if skip >= 3 and code_it.iterable[starting_pos + skip - 2] == sre_constants.JUMP:
                args['then'] = list(_get_instructions_inner(code_it, max_pos=inner_max_pos))
                jump_op = sre_constants.OPCODES[next(code_it)]
                if jump_op != sre_constants.JUMP:
                    raise InvalidCodeError('expected JUMP, got %r' % jump_op)
                _ensure_position(code_it, inner_max_pos + 1)
                skip = next(code_it)
                inner_max_pos = code_it.count + skip - 1
                args['jump_op'] = (jump_op, skip)
                args['else'] = list(_get_instructions_inner(code_it, max_pos=inner_max_pos))
                _ensure_position(code_it, inner_max_pos)
            else:
                args['then'] = list(_get_instructions_inner(code_it, max_pos=inner_max_pos))
                _ensure_position(code_it, inner_max_pos)

            yield (op, args)
        elif op in (sre_constants.ASSERT, sre_constants.ASSERT_NOT):
            skip = next(code_it)
            inner_max_pos = code_it.count + skip - 1
            width = next(code_it)
            if width & 0x80000000:
                raise InvalidCodeError('width too large')
            inner = _consume_and_ensure_following(
                _get_instructions_inner, code_it, inner_max_pos, sre_constants.SUCCESS)
            yield (op, {'skip': skip, 'width': width, 'inner': inner})
        else:
            assert False, 'unhandled opcode %r' % op
        if max_pos is not None and code_it.count == max_pos:
            break
    else:
        if max_pos is not None:
            raise InvalidCodeError('did not find enough codes')


def disassemble_charset(code_it, max_pos=None):
    for op in code_it:
        op = sre_constants.OPCODES[op]
        if op == sre_constants.NEGATE:
            yield (op, None)
        elif op == sre_constants.LITERAL:
            arg = next(code_it)
            yield (op, chr(arg))
        elif op in (sre_constants.RANGE, sre_constants.RANGE_IGNORE):
            start = next(code_it)
            stop = next(code_it)
            yield (op, (chr(start), chr(stop)))
        elif op == sre_constants.CHARSET:
            # 256-bit bitmap
            bits = list(islice(code_it, 256 // SRE_CODE_BITS))
            yield (op, bits)
        elif op == sre_constants.BIGCHARSET:
            # nested table of bitmaps
            num_blocks = next(code_it)
            contents_offset = 256 / SIZEOF_SRE_CODE
            contents = list(islice(code_it, contents_offset))
            blocks = []
            for _ in range(num_blocks):
                blocks.append(list(islice(code_it, 256 // SRE_CODE_BITS)))
            yield (op, (num_blocks, contents, blocks))
        elif op == sre_constants.CATEGORY:
            arg = next(code_it)
            category = sre_constants.CHCODES[arg]
            yield (op, category)
        else:
            assert False, 'unhandled opcode %r' % op
        if max_pos is not None and code_it.count == max_pos:
            break
    else:
        if max_pos is not None:
            raise InvalidCodeError('did not find enough codes')


def _disassemble_branch(code_it):
    codes = []
    targets = []
    while True:
        skip = next(code_it)
        max_pos = code_it.count + skip - 1
        if skip == 0:
            break
        inner = list(_get_instructions_inner(code_it, max_pos=code_it.count + skip - 3))
        next_op = sre_constants.OPCODES[next(code_it)]
        if next_op != sre_constants.JUMP:
            raise InvalidCodeError('branch must be followed by JUMP (got %r)' % next_op)
        end_skip = next(code_it)
        inner.append((next_op, end_skip))

        codes.append(inner)
        targets.append(code_it.count + end_skip - 1)
        _ensure_position(code_it, max_pos)

    if len(set(targets)) != 1:
        raise InvalidCodeError('Not all targets are the same: %s' % targets)
    return codes


def _disassemble_info(code_it):
    args = {}
    skip = args['skip'] = next(code_it)
    end_pos = code_it.count + skip - 1
    flags = args['flags'] = next(code_it)
    args['min'] = next(code_it)
    args['max'] = next(code_it)
    if (flags & ~(sre_constants.SRE_INFO_PREFIX |
                  sre_constants.SRE_INFO_LITERAL |
                  sre_constants.SRE_INFO_CHARSET)) != 0:
        raise InvalidCodeError('invalid flags %r' % flags)
    if ((flags & sre_constants.SRE_INFO_PREFIX) and
            (flags & sre_constants.SRE_INFO_CHARSET)):
        raise InvalidCodeError('PREFIX and CHARSET are mutually exclusive')
    if ((flags & sre_constants.SRE_INFO_LITERAL) and
            not (flags & sre_constants.SRE_INFO_PREFIX)):
        raise InvalidCodeError('LITERAL implies PREFIX')

    if flags & sre_constants.SRE_INFO_PREFIX:
        prefix_len = next(code_it)
        ignored = next(code_it)
        chars = ''.join(map(chr, islice(code_it, prefix_len)))
        overlap_table = tuple(islice(code_it, prefix_len))
        args['prefix'] = {
            'prefix_len': prefix_len,
            'ignored': ignored,
            'chars': chars,
            'overlap_table': overlap_table,
        }
    if flags & sre_constants.SRE_INFO_CHARSET:
        args['charset'] = _consume_and_ensure_following(
            disassemble_charset, code_it, end_pos, sre_constants.FAILURE)
    if code_it.count != end_pos:
        raise InvalidCodeError('incorrect skip in INFO')
    return args


def _ensure_position(code_it, pos):
    if code_it.count != pos:
        raise InvalidCodeError('incorrect skip (%s vs. %s)' % (code_it.count, pos))


def _consume_and_ensure_following(fn, code_it, max_pos, next_code):
    inner = list(fn(code_it, max_pos=max_pos - 1))
    next_op = sre_constants.OPCODES[next(code_it)]
    if next_op != next_code:
        raise InvalidCodeError('Expected %s, got %s' % (next_code, next_op))
    inner.append((next_op, None))
    return inner


class _CountingIterator(object):
    """Iterator wrapper that keeps track of how many items have been consumed."""
    def __init__(self, iterable):
        self.iterable = iterable
        self.iterator = iter(iterable)
        self.count = 0

    def __iter__(self):
        return self

    def __next__(self):
        value = next(self.iterator)
        self.count += 1
        return value
