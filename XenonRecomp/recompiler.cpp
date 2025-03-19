#include "pch.h"
#include "recompiler.h"
#include <xex_patcher.h>

static uint64_t ComputeMask(uint32_t mstart, uint32_t mstop)
{
    mstart &= 0x3F;
    mstop &= 0x3F;
    uint64_t value = (UINT64_MAX >> mstart) ^ ((mstop >= 63) ? 0 : UINT64_MAX >> (mstop + 1));
    return mstart <= mstop ? value : ~value;
}

bool Recompiler::LoadConfig(const std::string_view& configFilePath)
{
    config.Load(configFilePath);

    std::vector<uint8_t> file;
    if (!config.patchedFilePath.empty())
        file = LoadFile((config.directoryPath + config.patchedFilePath).c_str());

    if (file.empty())
    {
        file = LoadFile((config.directoryPath + config.filePath).c_str());

        if (!config.patchFilePath.empty())
        {
            const auto patchFile = LoadFile((config.directoryPath + config.patchFilePath).c_str());
            if (!patchFile.empty())
            {
                std::vector<uint8_t> outBytes;
                auto result = XexPatcher::apply(file.data(), file.size(), patchFile.data(), patchFile.size(), outBytes, false);
                if (result == XexPatcher::Result::Success)
                {
                    std::exchange(file, outBytes);

                    if (!config.patchedFilePath.empty())
                    {
                        std::ofstream stream(config.directoryPath + config.patchedFilePath, std::ios::binary);
                        if (stream.good())
                        {
                            stream.write(reinterpret_cast<const char*>(file.data()), file.size());
                            stream.close();
                        }
                    }
                }
                else
                {
                    fmt::print("ERROR: Unable to apply the patch file, ");

                    switch (result)
                    {
                    case XexPatcher::Result::XexFileUnsupported:
                        fmt::println("XEX file unsupported");
                        break;

                    case XexPatcher::Result::XexFileInvalid:
                        fmt::println("XEX file invalid");
                        break;

                    case XexPatcher::Result::PatchFileInvalid:
                        fmt::println("patch file invalid");
                        break;

                    case XexPatcher::Result::PatchIncompatible:
                        fmt::println("patch file incompatible");
                        break;

                    case XexPatcher::Result::PatchFailed:
                        fmt::println("patch failed");
                        break;

                    case XexPatcher::Result::PatchUnsupported:
                        fmt::println("patch unsupported");
                        break;

                    default:
                        fmt::println("reason unknown");
                        break;
                    }

                    return false;
                }
            }
            else
            {
                fmt::println("ERROR: Unable to load the patch file");
                return false;
            }
        }
    }

    image = Image::ParseImage(file.data(), file.size());
    return true;
}

void Recompiler::Analyse()
{
    for (size_t i = 14; i < 128; i++)
    {
        if (i < 32)
        {
            if (config.restGpr14Address != 0)
            {
                auto& restgpr = functions.emplace_back();
                restgpr.base = config.restGpr14Address + (i - 14) * 4;
                restgpr.size = (32 - i) * 4 + 12;
                image.symbols.emplace(Symbol{ fmt::format("__restgprlr_{}", i), restgpr.base, restgpr.size, Symbol_Function });
            }

            if (config.saveGpr14Address != 0)
            {
                auto& savegpr = functions.emplace_back();
                savegpr.base = config.saveGpr14Address + (i - 14) * 4;
                savegpr.size = (32 - i) * 4 + 8;
                image.symbols.emplace(fmt::format("__savegprlr_{}", i), savegpr.base, savegpr.size, Symbol_Function);
            }

            if (config.restFpr14Address != 0)
            {
                auto& restfpr = functions.emplace_back();
                restfpr.base = config.restFpr14Address + (i - 14) * 4;
                restfpr.size = (32 - i) * 4 + 4;
                image.symbols.emplace(fmt::format("__restfpr_{}", i), restfpr.base, restfpr.size, Symbol_Function);
            }

            if (config.saveFpr14Address != 0)
            {
                auto& savefpr = functions.emplace_back();
                savefpr.base = config.saveFpr14Address + (i - 14) * 4;
                savefpr.size = (32 - i) * 4 + 4;
                image.symbols.emplace(fmt::format("__savefpr_{}", i), savefpr.base, savefpr.size, Symbol_Function);
            }

            if (config.restVmx14Address != 0)
            {
                auto& restvmx = functions.emplace_back();
                restvmx.base = config.restVmx14Address + (i - 14) * 8;
                restvmx.size = (32 - i) * 8 + 4;
                image.symbols.emplace(fmt::format("__restvmx_{}", i), restvmx.base, restvmx.size, Symbol_Function);
            }

            if (config.saveVmx14Address != 0)
            {
                auto& savevmx = functions.emplace_back();
                savevmx.base = config.saveVmx14Address + (i - 14) * 8;
                savevmx.size = (32 - i) * 8 + 4;
                image.symbols.emplace(fmt::format("__savevmx_{}", i), savevmx.base, savevmx.size, Symbol_Function);
            }
        }

        if (i >= 64)
        {
            if (config.restVmx64Address != 0)
            {
                auto& restvmx = functions.emplace_back();
                restvmx.base = config.restVmx64Address + (i - 64) * 8;
                restvmx.size = (128 - i) * 8 + 4;
                image.symbols.emplace(fmt::format("__restvmx_{}", i), restvmx.base, restvmx.size, Symbol_Function);
            }

            if (config.saveVmx64Address != 0)
            {
                auto& savevmx = functions.emplace_back();
                savevmx.base = config.saveVmx64Address + (i - 64) * 8;
                savevmx.size = (128 - i) * 8 + 4;
                image.symbols.emplace(fmt::format("__savevmx_{}", i), savevmx.base, savevmx.size, Symbol_Function);
            }
        }
    }

    for (auto& [address, size] : config.functions)
    {
        functions.emplace_back(address, size);
        image.symbols.emplace(fmt::format("sub_{:X}", address), address, size, Symbol_Function);
    }

    auto& pdata = *image.Find(".pdata");
    size_t count = pdata.size / sizeof(IMAGE_CE_RUNTIME_FUNCTION);
    auto* pf = (IMAGE_CE_RUNTIME_FUNCTION*)pdata.data;
    for (size_t i = 0; i < count; i++)
    {
        auto fn = pf[i];
        fn.BeginAddress = ByteSwap(fn.BeginAddress);
        fn.Data = ByteSwap(fn.Data);

        if (image.symbols.find(fn.BeginAddress) == image.symbols.end())
        {
            auto& f = functions.emplace_back();
            f.base = fn.BeginAddress;
            f.size = fn.FunctionLength * 4;

            image.symbols.emplace(fmt::format("sub_{:X}", f.base), f.base, f.size, Symbol_Function);
        }
    }

    for (const auto& section : image.sections)
    {
        if (!(section.flags & SectionFlags_Code))
        {
            continue;
        }
        size_t base = section.base;
        uint8_t* data = section.data;
        uint8_t* dataEnd = section.data + section.size;

        while (data < dataEnd)
        {
            uint32_t insn = ByteSwap(*(uint32_t*)data);
            if (PPC_OP(insn) == PPC_OP_B && PPC_BL(insn))
            {
                size_t address = base + (data - section.data) + PPC_BI(insn);

                if (address >= section.base && address < section.base + section.size && image.symbols.find(address) == image.symbols.end())
                {
                    auto data = section.data + address - section.base;
                    auto& fn = functions.emplace_back(Function::Analyze(data, section.base + section.size - address, address));
                    image.symbols.emplace(fmt::format("sub_{:X}", fn.base), fn.base, fn.size, Symbol_Function);
                }
            }
            data += 4;
        }

        data = section.data;

        while (data < dataEnd)
        {
            auto invalidInstr = config.invalidInstructions.find(ByteSwap(*(uint32_t*)data));
            if (invalidInstr != config.invalidInstructions.end())
            {
                base += invalidInstr->second;
                data += invalidInstr->second;
                continue;
            }

            auto fnSymbol = image.symbols.find(base);
            if (fnSymbol != image.symbols.end() && fnSymbol->address == base && fnSymbol->type == Symbol_Function)
            {
                assert(fnSymbol->address == base);

                base += fnSymbol->size;
                data += fnSymbol->size;
            }
            else
            {
                auto& fn = functions.emplace_back(Function::Analyze(data, dataEnd - data, base));
                image.symbols.emplace(fmt::format("sub_{:X}", fn.base), fn.base, fn.size, Symbol_Function);

                base += fn.size;
                data += fn.size;
            }
        }
    }

    std::sort(functions.begin(), functions.end(), [](auto& lhs, auto& rhs) { return lhs.base < rhs.base; });
}

bool Recompiler::Recompile(
    const Function& fn,
    uint32_t base,
    const ppc_insn& insn,
    const uint32_t* data,
    std::unordered_map<uint32_t, RecompilerSwitchTable>::iterator& switchTable,
    RecompilerLocalVariables& localVariables,
    CSRState& csrState)
{
    println("\t// {} {}", insn.opcode->name, insn.op_str);

    // TODO: we could cache these formats in an array
    auto r = [&](size_t index)
        {
            if ((config.nonArgumentRegistersAsLocalVariables && (index == 0 || index == 2 || index == 11 || index == 12)) || 
                (config.nonVolatileRegistersAsLocalVariables && index >= 14))
            {
                localVariables.r[index] = true;
                return fmt::format("r{}", index);
            }
            return fmt::format("ctx.r{}", index);
        };

    auto f = [&](size_t index)
        {
            if ((config.nonArgumentRegistersAsLocalVariables && index == 0) ||
                (config.nonVolatileRegistersAsLocalVariables && index >= 14))
            {
                localVariables.f[index] = true;
                return fmt::format("f{}", index);
            }
            return fmt::format("ctx.f{}", index);
        };

    auto v = [&](size_t index)
        {
            if ((config.nonArgumentRegistersAsLocalVariables && (index >= 32 && index <= 63)) ||
                (config.nonVolatileRegistersAsLocalVariables && ((index >= 14 && index <= 31) || (index >= 64 && index <= 127))))
            {
                localVariables.v[index] = true;
                return fmt::format("v{}", index);
            }
            return fmt::format("ctx.v{}", index);
        };

    auto cr = [&](size_t index)
        {
            if (config.crRegistersAsLocalVariables)
            {
                localVariables.cr[index] = true;
                return fmt::format("cr{}", index);
            }
            return fmt::format("ctx.cr{}", index);
        };

    auto ctr = [&]()
        {
            if (config.ctrAsLocalVariable)
            {
                localVariables.ctr = true;
                return "ctr";
            }
            return "ctx.ctr";
        };

    auto xer = [&]()
        {
            if (config.xerAsLocalVariable)
            {
                localVariables.xer = true;
                return "xer";
            }
            return "ctx.xer";
        };

    auto reserved = [&]()
        {
            if (config.reservedRegisterAsLocalVariable)
            {
                localVariables.reserved = true;
                return "reserved";
            }
            return "ctx.reserved";
        };

    auto temp = [&]()
        {
            localVariables.temp = true;
            return "temp";
        };

    auto vTemp = [&]()
        {
            localVariables.vTemp = true;
            return "vTemp";
        };

    auto env = [&]()
        {
            localVariables.env = true;
            return "env";
        };

    auto ea = [&]()
        {
            localVariables.ea = true;
            return "ea";
        };

    auto lr = [&]()
        {
            return "ctx.lr";
        };

    auto pc = [&]()
        {
            return "ctx.pc";
        };

    // TODO (Sajid): Check for out of bounds access
    auto mmioStore = [&]() -> bool
        {
            return *(data + 1) == c_eieio;
        };

    auto printFunctionCall = [&](uint32_t address)
        {
            if (address == config.longJmpAddress)
            {
                println("\tlongjmp(*reinterpret_cast<jmp_buf*>(base + {}.u32), {}.s32);", r(3), r(4));
            }
            else if (address == config.setJmpAddress)
            {
                println("\t{} = ctx;", env());
                println("\t{}.s64 = setjmp(*reinterpret_cast<jmp_buf*>(base + {}.u32));", r(3), r(3));
                println("\tif ({}.s64 != 0) ctx = {};", r(3), env());
            }
            else
            {
                auto targetSymbol = image.symbols.find(address);

                if (targetSymbol != image.symbols.end() && targetSymbol->address == address && targetSymbol->type == Symbol_Function)
                {
                    if (config.nonVolatileRegistersAsLocalVariables && (targetSymbol->name.find("__rest") == 0 || targetSymbol->name.find("__save") == 0))
                    {
                        // print nothing
                    }
                    else
                    {
                        println("\t{}(ctx, base);", targetSymbol->name);
                    }
                }
                else
                {
                    println("\t// ERROR {:X}", address);
                }
            }
        };

    auto printConditionalBranch = [&](bool not_, const std::string_view& cond)
        {
            if (insn.operands[1] < fn.base || insn.operands[1] >= fn.base + fn.size)
            {
                println("\tif ({}{}.{}) {{", not_ ? "!" : "", cr(insn.operands[0]), cond);
                print("\t");
                printFunctionCall(insn.operands[1]);
                println("\t\treturn;");
                println("\t}}");
            }
            else
            {
                println("\tif ({}{}.{}) goto loc_{:X};", not_ ? "!" : "", cr(insn.operands[0]), cond, insn.operands[1]);
            }
        };

    auto printSetFlushMode = [&](bool enable)
        {
            auto newState = enable ? CSRState::VMX : CSRState::FPU;
            if (csrState != newState)
            {
                auto prefix = enable ? "enable" : "disable";
                auto suffix = csrState != CSRState::Unknown ? "Unconditional" : "";
                println("\tctx.fpscr.{}FlushMode{}();", prefix, suffix);

                csrState = newState;
            }
        };

    auto midAsmHook = config.midAsmHooks.find(base);

    auto printMidAsmHook = [&]()
        {
            bool returnsBool = midAsmHook->second.returnOnFalse || midAsmHook->second.returnOnTrue ||
                midAsmHook->second.jumpAddressOnFalse != 0 || midAsmHook->second.jumpAddressOnTrue != 0;

            print("\t");
            if (returnsBool)
                print("if (");

            print("{}(", midAsmHook->second.name);
            for (auto& reg : midAsmHook->second.registers)
            {
                if (out.back() != '(')
                    out += ", ";

                switch (reg[0])
                {
                case 'c':
                    if (reg == "ctr")
                        out += ctr();
                    else
                        out += cr(std::atoi(reg.c_str() + 2));
                    break;

                case 'x':
                    out += xer();
                    break;

                case 'r':
                    if (reg == "reserved")
                        out += reserved();
                    else
                        out += r(std::atoi(reg.c_str() + 1));
                    break;

                case 'f':
                    if (reg == "fpscr")
                        out += "ctx.fpscr";
                    else
                        out += f(std::atoi(reg.c_str() + 1));
                    break;

                case 'v':
                    out += v(std::atoi(reg.c_str() + 1));
                    break;
                }
            }

            if (returnsBool)
            {
                println(")) {{");

                if (midAsmHook->second.returnOnTrue)
                    println("\t\treturn;");
                else if (midAsmHook->second.jumpAddressOnTrue != 0)
                    println("\t\tgoto loc_{:X};", midAsmHook->second.jumpAddressOnTrue);

                println("\t}}");

                println("\telse {{");

                if (midAsmHook->second.returnOnFalse)
                    println("\t\treturn;");
                else if (midAsmHook->second.jumpAddressOnFalse != 0)
                    println("\t\tgoto loc_{:X};", midAsmHook->second.jumpAddressOnFalse);

                println("\t}}");
            }
            else
            {
                println(");");

                if (midAsmHook->second.ret)
                    println("\treturn;");
                else if (midAsmHook->second.jumpAddress != 0)
                    println("\tgoto loc_{:X};", midAsmHook->second.jumpAddress);
            }
        };

    if (midAsmHook != config.midAsmHooks.end() && !midAsmHook->second.afterInstruction)
        printMidAsmHook();

    int id = insn.opcode->id;

    // Handling instructions that don't disassemble correctly for some reason here
    if (id == PPC_INST_VUPKHSB128 && insn.operands[2] == 0x60) id = PPC_INST_VUPKHSH128;
    else if (id == PPC_INST_VUPKLSB128 && insn.operands[2] == 0x60) id = PPC_INST_VUPKLSH128;

    switch (id)
    {
    case PPC_INST_ADD:
        println("\t{}.u64 = {}.u64 + {}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ADDE:
        println("\t{}.u8 = ({}.u32 + {}.u32 < {}.u32) | ({}.u32 + {}.u32 + {}.ca < {}.ca);", temp(), r(insn.operands[1]), r(insn.operands[2]), r(insn.operands[1]), r(insn.operands[1]), r(insn.operands[2]), xer(), xer());
        println("\t{}.u64 = {}.u64 + {}.u64 + {}.ca;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]), xer());
        println("\t{}.ca = {}.u8;", xer(), temp());
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ADDI:
        print("\t{}.s64 = ", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.s64 + ", r(insn.operands[1]));
        println("{};", int32_t(insn.operands[2]));
        break;

    case PPC_INST_ADDIC:
        println("\t{}.ca = {}.u32 > {};", xer(), r(insn.operands[1]), ~insn.operands[2]);
        println("\t{}.s64 = {}.s64 + {};", r(insn.operands[0]), r(insn.operands[1]), int32_t(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ADDIS:
        print("\t{}.s64 = ", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.s64 + ", r(insn.operands[1]));
        println("{};", static_cast<int32_t>(insn.operands[2] << 16));
        break;

    case PPC_INST_ADDZE:
        println("\t{}.s64 = {}.s64 + {}.ca;", temp(), r(insn.operands[1]), xer());
        println("\t{}.ca = {}.u32 < {}.u32;", xer(), temp(), r(insn.operands[1]));
        println("\t{}.s64 = {}.s64;", r(insn.operands[0]), temp());
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_AND:
        println("\t{}.u64 = {}.u64 & {}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ANDC:
        println("\t{}.u64 = {}.u64 & ~{}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ANDI:
        println("\t{}.u64 = {}.u64 & {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2]);
        println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ANDIS:
        println("\t{}.u64 = {}.u64 & {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2] << 16);
        println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ATTN:
        // undefined instruction
        break;

    case PPC_INST_B:
        if (insn.operands[0] < fn.base || insn.operands[0] >= fn.base + fn.size)
        {
            printFunctionCall(insn.operands[0]);
            println("\treturn;");
        }
        else
        {
            println("\tgoto loc_{:X};", insn.operands[0]);
        }
        break;

    case PPC_INST_BCTR:
        if (switchTable != config.switchTables.end())
        {
            println("\tswitch ({}.u64) {{", r(switchTable->second.r));

            for (size_t i = 0; i < switchTable->second.labels.size(); i++)
            {
                println("\tcase {}:", i);
                auto label = switchTable->second.labels[i];
                if (label < fn.base || label >= fn.base + fn.size)
                {
                    println("\t\t// ERROR: 0x{:X}", label);
                    fmt::println("ERROR: Switch case at {:X} is trying to jump outside function: {:X}", base, label);
                    println("\t\treturn;");
                }
                else
                {
                    println("\t\tgoto loc_{:X};", label);
                }
            }

            println("\tdefault:");
            println("\t\t__builtin_unreachable();");
            println("\t}}");

            switchTable = config.switchTables.end();
        }
        else
        {
            println("\tPPC_CALL_INDIRECT_FUNC({}.u32);", ctr());
            println("\treturn;");
        }
        break;

    case PPC_INST_BCTRL:
        if (!config.skipLr)
            println("\tctx.lr = 0x{:X};", base + 4);
        println("\tPPC_CALL_INDIRECT_FUNC({}.u32);", ctr());
        csrState = CSRState::Unknown; // the call could change it
        break;

    case PPC_INST_BDZ:
        println("\t--{}.u64;", ctr());
        println("\tif ({}.u32 == 0) goto loc_{:X};", ctr(), insn.operands[0]);
        break;

    case PPC_INST_BDZLR:
        println("\t--{}.u64;", ctr());
        println("\tif ({}.u32 == 0) return;", ctr(), insn.operands[0]);
        break;

    case PPC_INST_BDNZ:
        println("\t--{}.u64;", ctr());
        println("\tif ({}.u32 != 0) goto loc_{:X};", ctr(), insn.operands[0]);
        break;

    case PPC_INST_BDNZF:
        // NOTE: assuming eq here as a shortcut because all the instructions in the game do that
        println("\t--{}.u64;", ctr());
        println("\tif ({}.u32 != 0 && !{}.eq) goto loc_{:X};", ctr(), cr(insn.operands[0] / 4), insn.operands[1]);
        break;

    case PPC_INST_BEQ:
        printConditionalBranch(false, "eq");
        break;

    case PPC_INST_BEQLR:
        println("\tif ({}.eq) return;", cr(insn.operands[0]));
        break;

    case PPC_INST_BGE:
        printConditionalBranch(true, "lt");
        break;

    case PPC_INST_BGELR:
        println("\tif (!{}.lt) return;", cr(insn.operands[0]));
        break;

    case PPC_INST_BGT:
        printConditionalBranch(false, "gt");
        break;

    case PPC_INST_BGTLR:
        println("\tif ({}.gt) return;", cr(insn.operands[0]));
        break;

    case PPC_INST_BL:
        if (!config.skipLr)
            println("\tctx.lr = 0x{:X};", base + 4);
        printFunctionCall(insn.operands[0]);
        csrState = CSRState::Unknown; // the call could change it
        break;

    case PPC_INST_BLE:
        printConditionalBranch(true, "gt");
        break;

    case PPC_INST_BLELR:
        println("\tif (!{}.gt) return;", cr(insn.operands[0]));
        break;

    case PPC_INST_BLR:
        println("\treturn;");
        break;

    case PPC_INST_BLRL:
        println("__builtin_debugtrap();");
        break;

    case PPC_INST_BLT:
        printConditionalBranch(false, "lt");
        break;

    case PPC_INST_BLTLR:
        println("\tif ({}.lt) return;", cr(insn.operands[0]));
        break;

    case PPC_INST_BNE:
        printConditionalBranch(true, "eq");
        break;

    case PPC_INST_BNELA:
        println("\tif({}.ne()) {{ {} = {:X}; }} else {{ {} = {}; }}", cr(insn.operands[0]), lr(), insn.operands[1], pc(), insn.operands[2]);
        break;

    case PPC_INST_BNELR:
        println("\tif (!{}.eq) return;", cr(insn.operands[0]));
        break;

    case PPC_INST_BNECTRL:
        println("\tif({}.ne()) {{ {} = {:X}; {} = {}; }}", cr(insn.operands[0]), lr(), insn.operands[1], pc(), ctr());
        break;

    case PPC_INST_BNEA:
        println("\tif({}.ne()) {{ {} = {}; }}", cr(insn.operands[0]), pc(), insn.operands[1]);
        break;

    case PPC_INST_BDNZA:
        println("\t{}.u64 = {}.u64 - 1;", ctr(), ctr());
        println("\tif({}.s32 != 0) {{ {} = {}; }}", ctr(), pc(), insn.operands[0]);
        break;

    case PPC_INST_BDNZL:
        println("\t{}.u64 = {}.u64 - 1;", ctr(), ctr());
        println("\tif({}.s32 != 0) {{ {} = {:X}; {} = {}; }}", ctr(), lr(), insn.operands[1], pc(), insn.operands[0]);
        break;

    case PPC_INST_BDNZLA:
        println("\t{}.u64 = {}.u64 - 1;", ctr(), ctr());
        println("\tif({}.s32 != 0) {{ {} = {:X}; {} = {}; }}", ctr(), lr(), insn.operands[1], pc(), insn.operands[0]);
        break;

    case PPC_INST_BCLR:
        println("\t{} = {};", pc(), lr());
        break;

    case PPC_INST_BCCTR:
        println("\t{} = {};", pc(), ctr());
        break;

    case PPC_INST_FNMADD:
        printSetFlushMode(false);
        println("\t{}.f64 = -({}.f64 * {}.f64 + {}.f64);", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.fpscr.setFlags({}.f64);", f(insn.operands[0]));
        break;

    case PPC_INST_LHBRX:
        println("\t{}.u16 = __builtin_bswap16(mem::loadVolatileU16<true>({} + {}));", r(insn.operands[0]), r(insn.operands[1] == 0 ? 0 : insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_VMINSW:
        printSetFlushMode(true);
        println("\t{}.s32[0] = std::min({}.s32[0], {}.s32[0]);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.s32[1] = std::min({}.s32[1], {}.s32[1]);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.s32[2] = std::min({}.s32[2], {}.s32[2]);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.s32[3] = std::min({}.s32[3], {}.s32[3]);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_STVEBX:
        println("\t{} = ({} + {}) & 0xFFFFFFFFFFFFFFF0;", ea(), r(insn.operands[1] == 0 ? 0 : insn.operands[1]), r(insn.operands[2]));
        println("\tmem::store8({}.u8[15 - (({} + {}) & 0xF)], (uint32_t){});", v(insn.operands[0]), r(insn.operands[1] == 0 ? 0 : insn.operands[1]), r(insn.operands[2]), ea());
        break;

    case PPC_INST_VAVGSW:
        printSetFlushMode(true);
        println("\t{}.s32[0] = ({}.s64[0] + {}.s64[0] + 1) >> 1;", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.s32[1] = ({}.s64[1] + {}.s64[1] + 1) >> 1;", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.s32[2] = ({}.s64[2] + {}.s64[2] + 1) >> 1;", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.s32[3] = ({}.s64[3] + {}.s64[3] + 1) >> 1;", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VSUBSBS:
        printSetFlushMode(true);
        println("\t{}.s8[0] = std::max(std::min({}.s8[0] - {}.s8[0], INT8_MAX), INT8_MIN);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.s8[1] = std::max(std::min({}.s8[1] - {}.s8[1], INT8_MAX), INT8_MIN);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.s8[2] = std::max(std::min({}.s8[2] - {}.s8[2], INT8_MAX), INT8_MIN);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.s8[3] = std::max(std::min({}.s8[3] - {}.s8[3], INT8_MAX), INT8_MIN);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.s8[4] = std::max(std::min({}.s8[4] - {}.s8[4], INT8_MAX), INT8_MIN);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.s8[5] = std::max(std::min({}.s8[5] - {}.s8[5], INT8_MAX), INT8_MIN);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.s8[6] = std::max(std::min({}.s8[6] - {}.s8[6], INT8_MAX), INT8_MIN);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.s8[7] = std::max(std::min({}.s8[7] - {}.s8[7], INT8_MAX), INT8_MIN);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.s8[8] = std::max(std::min({}.s8[8] - {}.s8[8], INT8_MAX), INT8_MIN);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.s8[9] = std::max(std::min({}.s8[9] - {}.s8[9], INT8_MAX), INT8_MIN);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.s8[10] = std::max(std::min({}.s8[10] - {}.s8[10], INT8_MAX), INT8_MIN);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.s8[11] = std::max(std::min({}.s8[11] - {}.s8[11], INT8_MAX), INT8_MIN);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.s8[12] = std::max(std::min({}.s8[12] - {}.s8[12], INT8_MAX), INT8_MIN);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.s8[13] = std::max(std::min({}.s8[13] - {}.s8[13], INT8_MAX), INT8_MIN);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.s8[14] = std::max(std::min({}.s8[14] - {}.s8[14], INT8_MAX), INT8_MIN);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.s8[15] = std::max(std::min({}.s8[15] - {}.s8[15], INT8_MAX), INT8_MIN);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VSLO:
        printSetFlushMode(true);
        println("\t{}.u8[0] = (({}.u8[15] << 3) | ({}.u8[0] >> 5)) & 0x7;", vTemp(), v(insn.operands[2]), v(insn.operands[2]));
        println("\tuint32_t shift = {}.u8[0];", vTemp());
        println("\tif (shift >= 16) {{");
        println("\t\t{}.u128 = _mm_setzero_si128();", v(insn.operands[0]));
        println("\t}} else {{");
        println("\t\t{}.u8[0] = (shift <= 0) ? {}.u8[0] : {}.u8[shift];", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[1]));
        println("\t\t{}.u8[1] = (shift <= 1) ? {}.u8[1] : {}.u8[shift + 1];", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[1]));
        println("\t\t{}.u8[2] = (shift <= 2) ? {}.u8[2] : {}.u8[shift + 2];", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[1]));
        println("\t\t{}.u8[3] = (shift <= 3) ? {}.u8[3] : {}.u8[shift + 3];", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[1]));
        println("\t\t{}.u8[4] = (shift <= 4) ? {}.u8[4] : {}.u8[shift + 4];", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[1]));
        println("\t\t{}.u8[5] = (shift <= 5) ? {}.u8[5] : {}.u8[shift + 5];", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[1]));
        println("\t\t{}.u8[6] = (shift <= 6) ? {}.u8[6] : {}.u8[shift + 6];", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[1]));
        println("\t\t{}.u8[7] = (shift <= 7) ? {}.u8[7] : {}.u8[shift + 7];", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[1]));
        println("\t\t{}.u8[8] = (shift <= 8) ? {}.u8[8] : {}.u8[shift + 8];", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[1]));
        println("\t\t{}.u8[9] = (shift <= 9) ? {}.u8[9] : {}.u8[shift + 9];", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[1]));
        println("\t\t{}.u8[10] = (shift <= 10) ? {}.u8[10] : {}.u8[shift + 10];", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[1]));
        println("\t\t{}.u8[11] = (shift <= 11) ? {}.u8[11] : {}.u8[shift + 11];", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[1]));
        println("\t\t{}.u8[12] = (shift <= 12) ? {}.u8[12] : {}.u8[shift + 12];", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[1]));
        println("\t\t{}.u8[13] = (shift <= 13) ? {}.u8[13] : {}.u8[shift + 13];", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[1]));
        println("\t\t{}.u8[14] = (shift <= 14) ? {}.u8[14] : {}.u8[shift + 14];", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[1]));
        println("\t\t{}.u8[15] = (shift <= 15) ? {}.u8[15] : {}.u8[shift + 15];", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[1]));
        println("\t}}");
        break;

    case PPC_INST_FDIVS:
        printSetFlushMode(false);
        println("\t{}.f64 = static_cast<float>({}.f64 / {}.f64);", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.fpscr.setFlags({}.f64);", f(insn.operands[0]));
        break;

    case PPC_INST_FMULS:
        printSetFlushMode(false);
        println("\t{}.f64 = static_cast<float>({}.f64 * {}.f64);", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.fpscr.setFlags({}.f64);", f(insn.operands[0]));
        break;

    case PPC_INST_FADDS:
        printSetFlushMode(false);
        println("\t{}.f64 = static_cast<float>({}.f64 + {}.f64);", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.fpscr.setFlags({}.f64);", f(insn.operands[0]));
        break;

    case PPC_INST_FRSP:
        printSetFlushMode(false);
        println("\t{}.f64 = static_cast<float>({}.f64);", f(insn.operands[0]), f(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.fpscr.setFlags({}.f64);", f(insn.operands[0]));
        break;

    case PPC_INST_FSUBS:
        printSetFlushMode(false);
        println("\t{}.f64 = static_cast<float>({}.f64 - {}.f64);", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.fpscr.setFlags({}.f64);", f(insn.operands[0]));
        break;

    case PPC_INST_FMSUBS:
        printSetFlushMode(false);
        println("\t{}.f64 = static_cast<float>({}.f64 * {}.f64 - {}.f64);", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.fpscr.setFlags({}.f64);", f(insn.operands[0]));
        break;

    case PPC_INST_FMADDS:
        printSetFlushMode(false);
        println("\t{}.f64 = static_cast<float>({}.f64 * {}.f64 + {}.f64);", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.fpscr.setFlags({}.f64);", f(insn.operands[0]));
        break;

    case PPC_INST_FCTIWZ:
        printSetFlushMode(false);
        println("\t{}.i64 = static_cast<int32_t>(std::trunc({}.f64));", f(insn.operands[0]), f(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.fpscr.setFlags({}.f64);", f(insn.operands[0]));
        break;

    case PPC_INST_VMAXSW:
        printSetFlushMode(true);
        println("\t{}.s32[0] = std::max({}.s32[0], {}.s32[0]);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.s32[1] = std::max({}.s32[1], {}.s32[1]);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.s32[2] = std::max({}.s32[2], {}.s32[2]);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.s32[3] = std::max({}.s32[3], {}.s32[3]);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VSLW:
        printSetFlushMode(true);
        println("\t{}.u32[0] = {}.u32[0] << ({}.u32[0] & 0x1F);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.u32[1] = {}.u32[1] << ({}.u32[1] & 0x1F);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.u32[2] = {}.u32[2] << ({}.u32[2] & 0x1F);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.u32[3] = {}.u32[3] << ({}.u32[3] & 0x1F);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VSLDOI:
        printSetFlushMode(true);
        println("\tuint32_t shift = {};", insn.operands[3]);
        println("\tif (shift == 0) {{");
        println("\t\t{}.u128 = {}.u128;", v(insn.operands[0]), v(insn.operands[1]));
        println("\t}} else if (shift == 16) {{");
        println("\t\t{}.u128 = {}.u128;", v(insn.operands[0]), v(insn.operands[2]));
        println("\t}} else {{");
        println("\t\t{}.u128 = _mm_or_si128(_mm_srli_si128({}.u128, 16 - shift), _mm_slli_si128({}.u128, shift));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t}}");
        break;

    case PPC_INST_STWBRX:
        println("\tmem::storeVolatileU32<true>(__builtin_bswap32({}.u32), ({} + {}));", r(insn.operands[0]), r(insn.operands[1] == 0 ? 0 : insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_VCMPEQUW:
        printSetFlushMode(true);
        println("\t{}.u32[0] = ({}.u32[0] == {}.u32[0]) ? 0xFFFFFFFF : 0;", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.u32[1] = ({}.u32[1] == {}.u32[1]) ? 0xFFFFFFFF : 0;", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.u32[2] = ({}.u32[2] == {}.u32[2]) ? 0xFFFFFFFF : 0;", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.u32[3] = ({}.u32[3] == {}.u32[3]) ? 0xFFFFFFFF : 0;", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VCMPEQFP:
        printSetFlushMode(true);
        println("\t{}.u32[0] = ({}.f32[0] == {}.f32[0]) ? 0xFFFFFFFF : 0;", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.u32[1] = ({}.f32[1] == {}.f32[1]) ? 0xFFFFFFFF : 0;", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.u32[2] = ({}.f32[2] == {}.f32[2]) ? 0xFFFFFFFF : 0;", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.u32[3] = ({}.f32[3] == {}.f32[3]) ? 0xFFFFFFFF : 0;", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VSPLTW:
        printSetFlushMode(true);
        println("\tuint32_t elem = {}.u32[{}];", v(insn.operands[1]), insn.operands[2] & 3);
        println("\t{}.u32[0] = elem;", v(insn.operands[0]));
        println("\t{}.u32[1] = elem;", v(insn.operands[0]));
        println("\t{}.u32[2] = elem;", v(insn.operands[0]));
        println("\t{}.u32[3] = elem;", v(insn.operands[0]));
        break;

    case PPC_INST_VSRW:
        printSetFlushMode(true);
        println("\t{}.u32[0] = {}.u32[0] >> ({}.u32[0] & 0x1F);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.u32[1] = {}.u32[1] >> ({}.u32[1] & 0x1F);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.u32[2] = {}.u32[2] >> ({}.u32[2] & 0x1F);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        println("\t{}.u32[3] = {}.u32[3] >> ({}.u32[3] & 0x1F);", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_FCMPU:
        printSetFlushMode(true);
        println("\tuint32_t cr = {};", insn.operands[0]);
        println("\tfloat a = {}.f64;", f(insn.operands[1]));
        println("\tfloat b = {}.f64;", f(insn.operands[2]));
        println("\tuint32_t flags = 0;");
        println("\tif (std::isnan(a) || std::isnan(b)) flags = 0x1;");
        println("\telse {");
        println("\t\tif (a < b) flags = 0x8;");
        println("\t\telse if (a > b) flags = 0x4;");
        println("\t\telse flags = 0x2;");
        println("\t}");
        println("\tstate.cr = (state.cr & ~(0xF << (4 * (7 - cr)))) | (flags << (4 * (7 - cr)));");
        break;

    case PPC_INST_FRES:
        printSetFlushMode(true);
        println("\t{}.f64 = 1.0 / {}.f64;", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FRSQRTE:
        printSetFlushMode(true);
        println("\t{}.f64 = 1.0 / std::sqrt({}.f64);", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_LVX:
        printSetFlushMode(true);
        println("\tuint32_t addr{} = ({} + {}) & ~0xF;", insn.operands[0], r(insn.operands[1] == 0 ? 0 : insn.operands[1]), r(insn.operands[2]));
        println("\t{}.u32[0] = mem::loadVolatileU32(addr{});", v(insn.operands[0]), insn.operands[0]);
        println("\t{}.u32[1] = mem::loadVolatileU32(addr{} + 4);", v(insn.operands[0]), insn.operands[0]);
        println("\t{}.u32[2] = mem::loadVolatileU32(addr{} + 8);", v(insn.operands[0]), insn.operands[0]);
        println("\t{}.u32[3] = mem::loadVolatileU32(addr{} + 12);", v(insn.operands[0]), insn.operands[0]);
        break;

    case PPC_INST_STVX:
        printSetFlushMode(true);
        println("\tuint32_t addr{} = ({} + {}) & ~0xF;", insn.operands[0], r(insn.operands[1] == 0 ? 0 : insn.operands[1]), r(insn.operands[2]));
        println("\tmem::storeVolatileU32({}.u32[0], addr{});", v(insn.operands[0]), insn.operands[0]);
        println("\tmem::storeVolatileU32({}.u32[1], addr{} + 4);", v(insn.operands[0]), insn.operands[0]);
        println("\tmem::storeVolatileU32({}.u32[2], addr{} + 8);", v(insn.operands[0]), insn.operands[0]);
        println("\tmem::storeVolatileU32({}.u32[3], addr{} + 12);", v(insn.operands[0]), insn.operands[0]);
        break;

    case PPC_INST_LFSX:
        printSetFlushMode(true);
        println("\t{}.f64 = (float)mem::loadVolatileF32({} + {});", f(insn.operands[0]), r(insn.operands[1] == 0 ? 0 : insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_STFSX:
        printSetFlushMode(true);
        println("\tmem::storeVolatileF32((float){}.f64, {} + {});", f(insn.operands[0]), r(insn.operands[1] == 0 ? 0 : insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_BGTLA:
        printSetFlushMode(true);
        println("\tif ((state.cr & (0x4 << (4 * (7 - {})))) != 0) {{", insn.operands[0]);
        println("\t\tstate.lr = insn.address + 4; // Set link register to next instruction address");
        println("\t\treturn {};", insn.operands[1]);
        println("\t}");
        break;

    case PPC_INST_MTCRF:
        printSetFlushMode(true);
        println("\tuint32_t mask = {};", insn.operands[0]);
        println("\tuint32_t value = {};", r(insn.operands[1]));
        println("\t// Apply each field selected by mask bits");
        println("\tfor (int i = 0; i < 8; i++) {");
        println("\t\tif (mask & (1 << (7 - i))) {");
        println("\t\t\tstate.cr = (state.cr & ~(0xF << (i * 4))) | ((value & (0xF << (i * 4))) << (i * 4));");
        println("\t\t}");
        println("\t}");
        break;

    case PPC_INST_MFCR:
        printSetFlushMode(true);
        println("\t{} = state.cr;", r(insn.operands[0]));
        break;

    default:
        return false;
    }

#if 1
    if (strchr(insn.opcode->name, '.'))
    {
        int lastLine = out.find_last_of('\n', out.size() - 2);
        if (out.find("cr0", lastLine + 1) == std::string::npos && out.find("cr6", lastLine + 1) == std::string::npos)
            fmt::println("{} at {:X} has RC bit enabled but no comparison was generated", insn.opcode->name, base);
    }
#endif

    if (midAsmHook != config.midAsmHooks.end() && midAsmHook->second.afterInstruction)
        printMidAsmHook();

    return true;
}

bool Recompiler::Recompile(const Function& fn)
{
    // Create a function with appropriate name
    auto fnSymbol = image.symbols.find(fn.base);
    if (fnSymbol == image.symbols.end())
    {
        fmt::println("ERROR: Symbol not found for function at address 0x{:X}", fn.base);
        return false;
    }

    println("void {}(PPCContext& ctx, uint8_t* base)\n{{", fnSymbol->name);

    RecompilerLocalVariables localVariables;
    
    auto switchTable = config.switchTables.find(fn.base);
    CSRState csrState = CSRState::Unknown;

    // Find the section containing this function
    const Section* section = nullptr;
    for (const auto& s : image.sections)
    {
        if (fn.base >= s.base && fn.base < s.base + s.size)
        {
            section = &s;
            break;
        }
    }

    if (!section)
    {
        println("}} // ERROR: Section not found");
        return false;
    }

    // Calculate offset into section
    size_t offset = fn.base - section->base;
    const uint8_t* data = section->data + offset;

    // Disassemble
    for (size_t i = 0; i < fn.size; i += 4)
    {
        size_t base = fn.base + i;
        
        // Check if this address is the beginning of a block
        for (const auto& block : fn.blocks)
        {
            if (block.base == (i))
            {
                println("loc_{:X}:", base);
                break;
            }
        }

        // Read instruction
        const uint32_t* instrData = (const uint32_t*)(data + i);
        uint32_t instr = ByteSwap(*instrData);
        
        ppc_insn insn;
        if (decode_insn_ppc(base, nullptr, &insn) != 0)
        {
            println("\t// ERROR: Unable to decode {:08X}", instr);
            continue;
        }

        if (!Recompile(fn, base, insn, instrData, switchTable, localVariables, csrState))
        {
            println("\t// ERROR: Unable to recompile {:08X} ({})", instr, insn.opcode->name);
        }
    }

    println("}}");
    return true;
}

void Recompiler::Recompile(const std::filesystem::path& headerFilePath)
{
    out.reserve(10 * 1024 * 1024);

    {
        println("#pragma once");

        println("#ifndef PPC_CONFIG_H_INCLUDED");
        println("#define PPC_CONFIG_H_INCLUDED\n");

        if (config.skipLr)
            println("#define PPC_CONFIG_SKIP_LR");      
        if (config.ctrAsLocalVariable)
            println("#define PPC_CONFIG_CTR_AS_LOCAL");      
        if (config.xerAsLocalVariable)
            println("#define PPC_CONFIG_XER_AS_LOCAL");      
        if (config.reservedRegisterAsLocalVariable)
            println("#define PPC_CONFIG_RESERVED_AS_LOCAL");      
        if (config.skipMsr)
            println("#define PPC_CONFIG_SKIP_MSR");      
        if (config.crRegistersAsLocalVariables)
            println("#define PPC_CONFIG_CR_AS_LOCAL");      
        if (config.nonArgumentRegistersAsLocalVariables)
            println("#define PPC_CONFIG_NON_ARGUMENT_AS_LOCAL");   
        if (config.nonVolatileRegistersAsLocalVariables)
            println("#define PPC_CONFIG_NON_VOLATILE_AS_LOCAL");

        println("");

        println("#define PPC_IMAGE_BASE 0x{:X}ull", image.base);
        println("#define PPC_IMAGE_SIZE 0x{:X}ull", image.size);
        
        // Extract the address of the minimum code segment to store the function table at.
        size_t codeMin = ~0;
        size_t codeMax = 0;

        for (auto& section : image.sections)
        {
            if ((section.flags & SectionFlags_Code) != 0)
            {
                if (section.base < codeMin)
                    codeMin = section.base;

                if ((section.base + section.size) > codeMax)
                    codeMax = (section.base + section.size);
            }
        }

        println("#define PPC_CODE_BASE 0x{:X}ull", codeMin);
        println("#define PPC_CODE_SIZE 0x{:X}ull", codeMax - codeMin);

        println("");

        println("#ifdef PPC_INCLUDE_DETAIL");
        println("#include \"ppc_detail.h\"");
        println("#endif");

        println("\n#endif");

        SaveCurrentOutData("ppc_config.h");
    }

    {
        println("#pragma once");

        println("#include \"ppc_config.h\"\n");
        
        std::ifstream stream(headerFilePath);
        if (stream.good())
        {
            std::stringstream ss;
            ss << stream.rdbuf();
            out += ss.str();
        }

        SaveCurrentOutData("ppc_context.h");
    }

    {
        println("#pragma once\n");
        println("#include \"ppc_config.h\"");
        println("#include \"ppc_context.h\"\n");

        for (auto& symbol : image.symbols)
            println("PPC_EXTERN_FUNC({});", symbol.name);

        SaveCurrentOutData("ppc_recomp_shared.h");
    }

    {
        println("#include \"ppc_recomp_shared.h\"\n");

        println("PPCFuncMapping PPCFuncMappings[] = {{");
        for (auto& symbol : image.symbols)
            println("\t{{ 0x{:X}, {} }},", symbol.address, symbol.name);

        println("\t{{ 0, nullptr }}");
        println("}};");

        SaveCurrentOutData("ppc_func_mapping.cpp");
    }

    for (size_t i = 0; i < functions.size(); i++)
    {
        if ((i % 256) == 0)
        {
            SaveCurrentOutData();
            println("#include \"ppc_recomp_shared.h\"\n");
        }

        if ((i % 2048) == 0 || (i == (functions.size() - 1)))
            fmt::println("Recompiling functions... {}%", static_cast<float>(i + 1) / functions.size() * 100.0f);

        Recompile(functions[i]);
    }

    SaveCurrentOutData();
}

void Recompiler::SaveCurrentOutData(const std::string_view& name)
{
    if (!out.empty())
    {
        std::string cppName;

        if (name.empty())
        {
            cppName = fmt::format("ppc_recomp.{}.cpp", cppFileIndex);
            ++cppFileIndex;
        }

        bool shouldWrite = true;

        // Check if an identical file already exists first to not trigger recompilation
        std::string directoryPath = config.directoryPath;
        if (!directoryPath.empty())
            directoryPath += "/";

        std::string filePath = fmt::format("{}{}/{}", directoryPath, config.outDirectoryPath, name.empty() ? cppName : name);
        FILE* f = fopen(filePath.c_str(), "rb");
        if (f)
        {
            static std::vector<uint8_t> temp;

            fseek(f, 0, SEEK_END);
            long fileSize = ftell(f);
            if (fileSize == out.size())
            {
                fseek(f, 0, SEEK_SET);
                temp.resize(fileSize);
                fread(temp.data(), 1, fileSize, f);

                shouldWrite = !XXH128_isEqual(XXH3_128bits(temp.data(), temp.size()), XXH3_128bits(out.data(), out.size()));
            }
            fclose(f);
        }

        if (shouldWrite)
        {
            f = fopen(filePath.c_str(), "wb");
            fwrite(out.data(), 1, out.size(), f);
            fclose(f);
        }

        out.clear();
    }
}
