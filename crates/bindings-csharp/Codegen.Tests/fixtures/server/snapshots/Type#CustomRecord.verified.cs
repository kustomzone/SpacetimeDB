﻿//HintName: CustomRecord.cs
// <auto-generated />
#nullable enable

partial class CustomRecord : System.IEquatable<CustomRecord>, SpacetimeDB.BSATN.IStructuralReadWrite
{
    public void ReadFields(System.IO.BinaryReader reader)
    {
        IntField = BSATN.IntFieldRW.Read(reader);
        StringField = BSATN.StringFieldRW.Read(reader);
        NullableIntField = BSATN.NullableIntFieldRW.Read(reader);
        NullableStringField = BSATN.NullableStringFieldRW.Read(reader);
    }

    public void WriteFields(System.IO.BinaryWriter writer)
    {
        BSATN.IntFieldRW.Write(writer, IntField);
        BSATN.StringFieldRW.Write(writer, StringField);
        BSATN.NullableIntFieldRW.Write(writer, NullableIntField);
        BSATN.NullableStringFieldRW.Write(writer, NullableStringField);
    }

    public override string ToString() =>
        $"CustomRecord {{ IntField = {SpacetimeDB.BSATN.StringUtil.GenericToString(IntField)}, StringField = {SpacetimeDB.BSATN.StringUtil.GenericToString(StringField)}, NullableIntField = {SpacetimeDB.BSATN.StringUtil.GenericToString(NullableIntField)}, NullableStringField = {SpacetimeDB.BSATN.StringUtil.GenericToString(NullableStringField)} }}";

    public readonly partial struct BSATN : SpacetimeDB.BSATN.IReadWrite<CustomRecord>
    {
        internal static readonly SpacetimeDB.BSATN.I32 IntFieldRW = new();
        internal static readonly SpacetimeDB.BSATN.String StringFieldRW = new();
        internal static readonly SpacetimeDB.BSATN.ValueOption<
            int,
            SpacetimeDB.BSATN.I32
        > NullableIntFieldRW = new();
        internal static readonly SpacetimeDB.BSATN.RefOption<
            string,
            SpacetimeDB.BSATN.String
        > NullableStringFieldRW = new();

        public CustomRecord Read(System.IO.BinaryReader reader) =>
            SpacetimeDB.BSATN.IStructuralReadWrite.Read<CustomRecord>(reader);

        public void Write(System.IO.BinaryWriter writer, CustomRecord value)
        {
            value.WriteFields(writer);
        }

        public SpacetimeDB.BSATN.AlgebraicType.Ref GetAlgebraicType(
            SpacetimeDB.BSATN.ITypeRegistrar registrar
        ) =>
            registrar.RegisterType<CustomRecord>(_ => new SpacetimeDB.BSATN.AlgebraicType.Product(
                new SpacetimeDB.BSATN.AggregateElement[]
                {
                    new("IntField", IntFieldRW.GetAlgebraicType(registrar)),
                    new("StringField", StringFieldRW.GetAlgebraicType(registrar)),
                    new("NullableIntField", NullableIntFieldRW.GetAlgebraicType(registrar)),
                    new("NullableStringField", NullableStringFieldRW.GetAlgebraicType(registrar))
                }
            ));

        SpacetimeDB.BSATN.AlgebraicType SpacetimeDB.BSATN.IReadWrite<CustomRecord>.GetAlgebraicType(
            SpacetimeDB.BSATN.ITypeRegistrar registrar
        ) => GetAlgebraicType(registrar);
    }

    public override int GetHashCode()
    {
        return IntField.GetHashCode()
            ^ StringField.GetHashCode()
            ^ NullableIntField.GetHashCode()
            ^ (NullableStringField == null ? 0 : NullableStringField.GetHashCode());
    }

#nullable enable
    public bool Equals(CustomRecord? that)
    {
        if (((object?)that) == null)
        {
            return false;
        }
        return IntField.Equals(that.IntField)
            && StringField.Equals(that.StringField)
            && NullableIntField.Equals(that.NullableIntField)
            && (
                NullableStringField == null
                    ? that.NullableStringField == null
                    : NullableStringField.Equals(that.NullableStringField)
            );
    }

    public override bool Equals(object? that)
    {
        if (that == null)
        {
            return false;
        }
        var that_ = that as CustomRecord;
        if (((object?)that_) == null)
        {
            return false;
        }
        return Equals(that_);
    }

    public static bool operator ==(CustomRecord? this_, CustomRecord? that)
    {
        if (((object?)this_) == null || ((object?)that) == null)
        {
            return object.Equals(this_, that);
        }
        return this_.Equals(that);
    }

    public static bool operator !=(CustomRecord? this_, CustomRecord? that)
    {
        if (((object?)this_) == null || ((object?)that) == null)
        {
            return !object.Equals(this_, that);
        }
        return !this_.Equals(that);
    }
#nullable restore
} // CustomRecord
