-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Text; with Pkg_Deb_Relations; with Pkg_Selected_Catalog;
package Pkg_Deb_Final_Set with SPARK_Mode => Off is
   Max_Architectures : constant := 256;
   type Architecture_List is array (Positive range <>) of MC_Text.Value;
   type Finding_Kind is (Not_Checked, No_Violation, Architecture_Not_Enabled,
      Not_Coinstallable, Version_Skew, Missing_Dependency, Present_Conflict);
   type Finding is record
      Kind : Finding_Kind := Not_Checked;
      Original, Other_Original : Digest := Zero_Digest;
      Field : Pkg_Deb_Relations.Field_Kind := Pkg_Deb_Relations.Depends;
      Group_Number, Atom_Position : Natural := 0;
   end record;
   type Verification is private;
   procedure Check (Value : Pkg_Selected_Catalog.Catalog;
                     Native_Architecture : String; Enabled : Architecture_List;
                     Deadline : Counter; Result : out Verification; Status : out Outcome);
   function Passed (Result : Verification) return Boolean;
   function Catalog_Hash (Result : Verification) return Digest;
   function Architecture_Hash (Result : Verification) return Digest;
   function Fingerprint (Result : Verification) return Digest;
   function Diagnostic (Result : Verification) return Finding;
   -- Checks a prospective fully configured endpoint from a sealed native catalog.
   -- Depends/Pre-Depends require a provider for every alternative group; negative
   -- Conflicts/Breaks forbid matching capabilities of other packages. Same-name
   -- cross-architecture instances require Multi-Arch:same and equal DEB versions.
   -- Real and versioned/unversioned virtual capabilities retain architecture and
   -- provided versions. No caller-supplied capability or successful callback.
   -- Negative virtual matches follow the fixed unpack semantics: name and
   -- provided version, without architecture filtering. Conflicts self-name
   -- excludes all same-name instances; Breaks excludes only the declaring one.
   -- Enabled is an explicit policy input, not discovery of runnable hardware or
   -- authorization. Native must be present; all is implicit, never a native arch.
   -- Binary qualifiers are literal labels: source-template :native is not an
   -- alias for the deployment's native architecture. :any has its own rules.
   -- Weak dependencies remain planner policy; Built-Using is source retention;
   -- Replaces is ownership policy, not satisfaction or permission to overwrite.
   -- Endpoint validity does not prove unpack/configure order, Pre-Depends prior
   -- state, cycles, Essential/Protected removal, scripts/triggers, CAS retention,
   -- provenance/consent or root/boot admission. The input catalog is unchanged.
   -- Only a complete successful check returns hashes. A failure returns a
   -- language-neutral finding where applicable, never a partial success receipt.
   -- UID 0 is refused; deadline and outer resource limits remain mandatory.
private
   type Verification is record
      Complete : Boolean := False;
      Catalog, Architectures, Hash : Digest := Zero_Digest;
      Issue : Finding;
   end record;
end Pkg_Deb_Final_Set;
