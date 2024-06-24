﻿//HintName: FFI.cs

// <auto-generated />
#nullable enable

using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using SpacetimeDB.Internal.Module;
using static SpacetimeDB.Internal.FFI;
using static SpacetimeDB.Runtime;
using Buffer = SpacetimeDB.Internal.FFI.Buffer;

static class ModuleRegistration
{
    class InsertData : SpacetimeDB.Internal.IReducer
    {
        private static PublicTable.BSATN data = new();

        public SpacetimeDB.Internal.Module.ReducerDef MakeReducerDef(
            SpacetimeDB.BSATN.ITypeRegistrar registrar
        )
        {
            return new(
                "InsertData",
                new SpacetimeDB.BSATN.AggregateElement(
                    nameof(data),
                    data.GetAlgebraicType(registrar)
                )
            );
        }

        public void Invoke(BinaryReader reader, SpacetimeDB.ReducerContext ctx)
        {
            Reducers.InsertData(data.Read(reader));
        }
    }

    class InsertData2 : SpacetimeDB.Internal.IReducer
    {
        private static PublicTable.BSATN data = new();

        public SpacetimeDB.Internal.Module.ReducerDef MakeReducerDef(
            SpacetimeDB.BSATN.ITypeRegistrar registrar
        )
        {
            return new(
                "test_custom_name_and_reducer_ctx",
                new SpacetimeDB.BSATN.AggregateElement(
                    nameof(data),
                    data.GetAlgebraicType(registrar)
                )
            );
        }

        public void Invoke(BinaryReader reader, SpacetimeDB.ReducerContext ctx)
        {
            Test.NestingNamespaces.AndClasses.InsertData2(ctx, data.Read(reader));
        }
    }

#if EXPERIMENTAL_WASM_AOT
    // In AOT mode we're building a library.
    // Main method won't be called automatically, so we need to export it as a preinit function.
    [UnmanagedCallersOnly(EntryPoint = "__preinit__10_init_csharp")]
#else
    // Prevent trimming of FFI exports that are invoked from C and not visible to C# trimmer.
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(FFI))]
#endif
    public static void Main()
    {
        FFI.RegisterReducer<InsertData>();
        FFI.RegisterReducer<InsertData2>();
        FFI.RegisterTable<PrivateTable>();
        FFI.RegisterTable<PublicTable>();
    }

    // Exports only work from the main assembly, so we need to generate forwarding methods.
#if EXPERIMENTAL_WASM_AOT
    [UnmanagedCallersOnly(EntryPoint = "__describe_module__")]
    public static Buffer __describe_module__() => FFI.__describe_module__();

    [UnmanagedCallersOnly(EntryPoint = "__call_reducer__")]
    public static Buffer __call_reducer__(
        uint id,
        Buffer caller_identity,
        Buffer caller_address,
        ulong timestamp,
        Buffer args
    ) => FFI.__call_reducer__(id, caller_identity, caller_address, timestamp, args);
#endif
}
