﻿//HintName: Reducers.ScheduleImmediate.cs
// <auto-generated />
#nullable enable

partial class Reducers
{
    [System.Diagnostics.CodeAnalysis.Experimental("STDB_UNSTABLE")]
    public static void VolatileNonatomicScheduleImmediateScheduleImmediate(PublicTable data)
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        new PublicTable.BSATN().Write(writer, data);
        SpacetimeDB.Internal.IReducer.VolatileNonatomicScheduleImmediate(
            nameof(ScheduleImmediate),
            stream
        );
    }
} // Reducers
