// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN RUST INSTEAD.
// <auto-generated />

#nullable enable

using System;
using SpacetimeDB;
using System.Collections.Generic;
using System.Runtime.Serialization;

namespace SpacetimeDB.Internal
{
	[SpacetimeDB.Type]
	[DataContract]
	public partial class RawReducerDefV9
	{
		[DataMember(Name = "name")]
		public string Name;
		[DataMember(Name = "params")]
		public List<SpacetimeDB.BSATN.AggregateElement> Params;
		[DataMember(Name = "lifecycle")]
		public SpacetimeDB.Internal.Lifecycle? Lifecycle;

		public RawReducerDefV9(
			string Name,
			List<SpacetimeDB.BSATN.AggregateElement> Params,
			SpacetimeDB.Internal.Lifecycle? Lifecycle
		)
		{
			this.Name = Name;
			this.Params = Params;
			this.Lifecycle = Lifecycle;
		}

		public RawReducerDefV9()
		{
			this.Name = "";
			this.Params = new();
		}

	}
}
