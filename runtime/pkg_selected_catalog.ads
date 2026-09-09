-- SPDX-License-Identifier: MIT
with Ada.Finalization;
with MC_Types; use MC_Types;
with MC_Store; with Pkg_Deb_Fields; with Pkg_Deb_Relations; with Pkg_Payload_Index;
package Pkg_Selected_Catalog with SPARK_Mode => Off is
   Max_Packages : constant := Pkg_Payload_Index.Max_Packages;
   Max_Atoms : constant := 262_144;
   Max_Text_Bytes : constant := 64 * 1024 * 1024;
   type Catalog is new Ada.Finalization.Limited_Controlled with private;
   type Selection_Item is record
      Original, Control : Digest := Zero_Digest;
   end record;
   type Selection is array (Positive range <>) of Selection_Item;
   type Package_Record is record
      Original, Archive, Control : Digest := Zero_Digest;
      Identity : Pkg_Deb_Fields.Metadata;
   end record;
   procedure Add (Value : in out Catalog; Store : in out MC_Store.Store;
                  Original : Digest; Deadline : Counter; Status : out Outcome);
   procedure Seal (Value : in out Catalog; Selected : Selection;
                   Payload : Pkg_Payload_Index.Index; Deadline : Counter;
                   Status : out Outcome);
   procedure Clear (Value : in out Catalog);
   function Sealed (Value : Catalog) return Boolean;
   function Package_Count (Value : Catalog) return Natural;
   function Fingerprint (Value : Catalog) return Digest;
   function Payload_Hash (Value : Catalog) return Digest;
   function Matches_Payload (Value : Catalog; Payload : Pkg_Payload_Index.Index) return Boolean;
   procedure Read_Package (Value : Catalog; Position : Positive;
                           Item : out Package_Record; Status : out Outcome);
   function Atom_Count (Value : Catalog; Position : Positive;
                        Kind : Pkg_Deb_Relations.Field_Kind) return Natural;
   function Group_Count (Value : Catalog; Position : Positive;
                         Kind : Pkg_Deb_Relations.Field_Kind) return Natural;
   procedure Read_Atom (Value : Catalog; Position : Positive;
                        Kind : Pkg_Deb_Relations.Field_Kind; Atom_Position : Positive;
                        Item : out Pkg_Deb_Relations.Atom; Status : out Outcome);
   -- An immutable candidate, subordinate to the accepted root/catalog authority.
   -- Add reobserves the original's control metadata through native CAS readers;
   -- public Observation/Metadata records are not accepted as trusted inputs.
   -- Seal requires exact equality of selected originals, observed metadata and
   -- the sealed payload source set, including expected raw control hashes.
   -- Duplicate originals and duplicate (name, architecture) identities fail.
   -- Every relationship atom, qualifier, version and alternative group survives.
   -- Sources are sorted by original digest. No partial candidate is readable;
   -- every Add/Seal failure clears it, including a failed repeated Seal.
   -- Selection is a caller assertion, NOT authentication or resolver validation.
   -- Same-name cross-architecture coexistence, dependency/phase satisfaction,
   -- Replaces, effective ownership, effects, CAS pin closure and actual generation
   -- admission still need policy and execution guards. No installed DB is written.
   -- Retained payload hash binds the specific index, not a mutable reference.
   -- Callers must recheck Matches_Payload if they replace/clear their index.
   -- UID 0 is refused. Deadlines and aggregate bounds apply before publication.
private
   type Data;
   type Data_Access is access Data;
   type Catalog is new Ada.Finalization.Limited_Controlled with record
      State : Data_Access;
   end record;
   overriding procedure Finalize (Value : in out Catalog);
end Pkg_Selected_Catalog;
