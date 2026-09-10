-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Finalization;
with MC_Types; use MC_Types;
with MC_Text; with Pkg_Deb_Final_Set; with Pkg_Selected_Catalog;
package Pkg_Deb_Transition with SPARK_Mode => Off is
   Max_Changes : constant := 2 * Pkg_Selected_Catalog.Max_Packages;
   type Change_Kind is (Added, Removed, Upgraded, Downgraded, Repacked);
   type Change is record
      Kind : Change_Kind := Added;
      Name, Architecture, Before_Version, After_Version : MC_Text.Value;
      Before_Original, After_Original : Digest := Zero_Digest;
   end record;
   type Failure_Kind is (Not_Checked, None, Endpoint_Rejected, Protection_Migration_Required);
   type Finding is record
      Kind : Failure_Kind := Not_Checked;
      Before_Original, After_Original : Digest := Zero_Digest;
      Essential_Lost, Protected_Lost : Boolean := False;
      Endpoint : Pkg_Deb_Final_Set.Finding;
   end record;
   type Plan is new Ada.Finalization.Limited_Controlled with private;
   procedure Build (Before, After : Pkg_Selected_Catalog.Catalog;
                    Native_Architecture : String; Enabled : Pkg_Deb_Final_Set.Architecture_List;
                    Deadline : Counter; Result : in out Plan;
                    Issue : out Finding; Status : out Outcome);
   procedure Clear (Value : in out Plan);
   function Sealed (Value : Plan) return Boolean;
   function Count (Value : Plan) return Natural;
   function Before_Hash (Value : Plan) return Digest;
   function After_Hash (Value : Plan) return Digest;
   function Endpoint_Hash (Value : Plan) return Digest;
   function Fingerprint (Value : Plan) return Digest;
   procedure Read_Change (Value : Plan; Position : Positive; Item : out Change; Status : out Outcome);
   -- Derives an immutable delta from two sealed native catalogs and checks the
   -- target's mandatory endpoint relations. The baseline need not be a valid
   -- configured endpoint: repairing a broken baseline must remain possible.
   -- Ordinary transitions retain baseline Essential/Protected identity and flags.
   -- Removing, changing architecture, or clearing a protection flag requires a
   -- separate validated migration, which this API cannot grant. Provides and
   -- Replaces cannot impersonate that retained identity. No force/override input.
   -- Deltas are ordered by exact package name then architecture; semantic version
   -- order distinguishes upgrades/downgrades from same-version repacking.
   -- Changed architecture is removal plus addition, not an implicit crossgrade.
   -- All failures clear the old/partial result; inputs remain unchanged.
   -- This is not a phase schedule, installed database, baseline authentication,
   -- rollback-floor check, migration authorization or root/boot write grant.
   -- Admission must bind Before_Hash to the actual accepted generation under
   -- its guard. Effects, ownership and CAS retention are separate obligations.
   -- UID 0 is refused. Existing bounded catalogs and outer resource limits apply.
private
   type Data;
   type Data_Access is access Data;
   type Plan is new Ada.Finalization.Limited_Controlled with record
      State : Data_Access;
   end record;
   overriding procedure Finalize (Value : in out Plan);
end Pkg_Deb_Transition;
