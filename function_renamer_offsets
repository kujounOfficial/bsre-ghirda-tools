#Rename functions based on offsets from a JSON file, prefixing the name with "Possible".
#@author kujoun
#@category _NEW_
#@keybinding
#@menupath
#@toolbar

from __future__ import print_function
import json

from ghidra.program.model.symbol import SourceType

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def to_int_offset(value):
    """Convert a JSON value (int or hex/dec string) into an int."""
    if isinstance(value, bool):
        raise ValueError("Offset cannot be a bool: %r" % (value,))

    if isinstance(value, int):
        return value

    if isinstance(value, str):
        v = value.strip()
        if v.lower().startswith('0x'):
            return int(v, 16)
        return int(v)

    raise ValueError("Unsupported offset type: %r" % (value,))


def rename_function_at(prog, fm, sym_table, addr, new_name):
    """
    Finds the function at the given address and renames it to new_name.
    Returns a tuple (old_name, final_name, status), where status is one of:
      'renamed'      - successfully renamed
      'same_name'    - the function already had this name
      'no_function'  - there is no function at this address
    """
    fn = fm.getFunctionContaining(addr)

    if not fn:
        return None, None, 'no_function'

    old_name = fn.getName()

    if old_name == new_name:
        return old_name, new_name, 'same_name'

    # getSymbols returns an ArrayList in Jython/Ghidrathon — use list() instead of hasNext()
    existing_syms = list(sym_table.getSymbols(new_name, None))
    final_name = new_name
    if existing_syms:
        # Check whether the existing symbol isn't this same function
        if existing_syms[0].getAddress() != fn.getEntryPoint():
            final_name = new_name + "_dup"

    fn.getSymbol().setName(final_name, SourceType.USER_DEFINED)

    return old_name, final_name, 'renamed'


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------

def rename_from_offsets():
    prog = currentProgram()
    fm = prog.getFunctionManager()
    sym_table = prog.getSymbolTable()

    json_file = askFile("Select the JSON file with offsets", "Open")
    if not json_file:
        print("No file was selected.")
        return

    json_path = str(json_file.getAbsolutePath())
    print("Loading offsets from: " + json_path)

    with open(json_path, 'r') as f:
        offsets = json.load(f)

    # Default base is the current program's image base, but it can be
    # overridden (e.g. if the offsets came from a different load of the binary).
    default_base = prog.getImageBase().toString()
    base_str = askString(
        "Base address",
        "Image base that the offsets are added to:",
        default_base
    )
    base_addr = prog.getAddressFactory().getAddress(base_str)

    print("Using base address: " + str(base_addr))

    total       = 0
    renamed     = 0
    same_name   = 0
    no_function = 0
    failed      = 0

    tx = prog.startTransaction("possiblesig: rename functions from offsets")
    success_tx = False

    try:
        for name, raw_offset in offsets.items():
            total += 1

            try:
                offset = to_int_offset(raw_offset)
            except Exception as e:
                print("[ERROR] %s - invalid offset %r: %s" % (name, raw_offset, e))
                failed += 1
                continue

            try:
                addr = base_addr.add(offset)
            except Exception as e:
                print("[ERROR] %s - failed to build address from offset 0x%x: %s" % (name, offset, e))
                failed += 1
                continue

            new_name = "Possible" + name

            try:
                old_name, final_name, status = rename_function_at(prog, fm, sym_table, addr, new_name)
            except Exception as e:
                print("[ERROR] %s @ %s - renaming failed: %s" % (name, addr, e))
                failed += 1
                continue

            if status == 'no_function':
                print("[MISS]  %s @ %s (offset 0x%x) - no function found at this address" % (name, addr, offset))
                no_function += 1
            elif status == 'same_name':
                print("[SAME]  %s @ %s - name unchanged" % (new_name, addr))
                same_name += 1
            else:
                print("[OK]    %s @ %s  (was: %s)" % (final_name, addr, old_name))
                renamed += 1

        success_tx = True

    finally:
        prog.endTransaction(tx, success_tx)

    print("\n--- Done ---")
    print("Total entries    : %d" % total)
    print("Renamed          : %d" % renamed)
    print("Unchanged         : %d" % same_name)
    print("No function found : %d" % no_function)
    print("Errors           : %d" % failed)


rename_from_offsets()
