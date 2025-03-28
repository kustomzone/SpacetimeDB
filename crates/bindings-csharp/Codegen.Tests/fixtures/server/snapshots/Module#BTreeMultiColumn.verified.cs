﻿//HintName: BTreeMultiColumn.cs
// <auto-generated />
#nullable enable

partial struct BTreeMultiColumn
    : System.IEquatable<BTreeMultiColumn>,
        SpacetimeDB.BSATN.IStructuralReadWrite
{
    public void ReadFields(System.IO.BinaryReader reader)
    {
        X = BSATN.XRW.Read(reader);
        Y = BSATN.YRW.Read(reader);
        Z = BSATN.ZRW.Read(reader);
    }

    public void WriteFields(System.IO.BinaryWriter writer)
    {
        BSATN.XRW.Write(writer, X);
        BSATN.YRW.Write(writer, Y);
        BSATN.ZRW.Write(writer, Z);
    }

    public override string ToString() =>
        $"BTreeMultiColumn {{ X = {SpacetimeDB.BSATN.StringUtil.GenericToString(X)}, Y = {SpacetimeDB.BSATN.StringUtil.GenericToString(Y)}, Z = {SpacetimeDB.BSATN.StringUtil.GenericToString(Z)} }}";

    public readonly partial struct BSATN : SpacetimeDB.BSATN.IReadWrite<BTreeMultiColumn>
    {
        internal static readonly SpacetimeDB.BSATN.U32 XRW = new();
        internal static readonly SpacetimeDB.BSATN.U32 YRW = new();
        internal static readonly SpacetimeDB.BSATN.U32 ZRW = new();

        public BTreeMultiColumn Read(System.IO.BinaryReader reader) =>
            SpacetimeDB.BSATN.IStructuralReadWrite.Read<BTreeMultiColumn>(reader);

        public void Write(System.IO.BinaryWriter writer, BTreeMultiColumn value)
        {
            value.WriteFields(writer);
        }

        public SpacetimeDB.BSATN.AlgebraicType.Ref GetAlgebraicType(
            SpacetimeDB.BSATN.ITypeRegistrar registrar
        ) =>
            registrar.RegisterType<BTreeMultiColumn>(
                _ => new SpacetimeDB.BSATN.AlgebraicType.Product(
                    new SpacetimeDB.BSATN.AggregateElement[]
                    {
                        new("X", XRW.GetAlgebraicType(registrar)),
                        new("Y", YRW.GetAlgebraicType(registrar)),
                        new("Z", ZRW.GetAlgebraicType(registrar))
                    }
                )
            );

        SpacetimeDB.BSATN.AlgebraicType SpacetimeDB.BSATN.IReadWrite<BTreeMultiColumn>.GetAlgebraicType(
            SpacetimeDB.BSATN.ITypeRegistrar registrar
        ) => GetAlgebraicType(registrar);
    }

    public override int GetHashCode()
    {
        return X.GetHashCode() ^ Y.GetHashCode() ^ Z.GetHashCode();
    }

#nullable enable
    public bool Equals(BTreeMultiColumn that)
    {
        return X.Equals(that.X) && Y.Equals(that.Y) && Z.Equals(that.Z);
    }

    public override bool Equals(object? that)
    {
        if (that == null)
        {
            return false;
        }
        var that_ = that as BTreeMultiColumn?;
        if (((object?)that_) == null)
        {
            return false;
        }
        return Equals(that_);
    }

    public static bool operator ==(BTreeMultiColumn this_, BTreeMultiColumn that)
    {
        if (((object?)this_) == null || ((object?)that) == null)
        {
            return object.Equals(this_, that);
        }
        return this_.Equals(that);
    }

    public static bool operator !=(BTreeMultiColumn this_, BTreeMultiColumn that)
    {
        if (((object?)this_) == null || ((object?)that) == null)
        {
            return !object.Equals(this_, that);
        }
        return !this_.Equals(that);
    }
#nullable restore
} // BTreeMultiColumn
