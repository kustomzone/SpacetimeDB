﻿//HintName: TestIncompatibleSchedule.TestIncompatibleScheduleReducer.cs
// <auto-generated />
#nullable enable

partial struct TestIncompatibleSchedule
{
    [System.Diagnostics.CodeAnalysis.Experimental("STDB_UNSTABLE")]
    public static void VolatileNonatomicScheduleImmediateTestIncompatibleScheduleReducer(
        TestIncompatibleSchedule table
    )
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        new TestIncompatibleSchedule.BSATN().Write(writer, table);
        SpacetimeDB.Internal.IReducer.VolatileNonatomicScheduleImmediate(
            "TestIncompatibleScheduleReducer",
            stream
        );
    }
} // TestIncompatibleSchedule
