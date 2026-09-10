-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Finalization;
with MC_Types; use MC_Types;
with MC_Store; with Pkg_Deb_Payload;
package Pkg_Deb_Conffiles with SPARK_Mode => Off is
   Max_Entries : constant := 4_096;
   type Declaration is record
      Path : Pkg_Deb_Payload.Byte_Strings.Bounded_String; -- Absolute native byte pathname.
      Remove_On_Upgrade, Present : Boolean := False;
      Payload : Pkg_Deb_Payload.Payload_Entry;
   end record;
   type Inventory is new Ada.Finalization.Limited_Controlled with private;
   procedure Inspect (Store : in out MC_Store.Store; Original : Digest; Deadline : Counter;
      Value : in out Inventory; Status : out Outcome);
   procedure Clear (Value : in out Inventory);
   function Original_Hash (Value : Inventory) return Digest;
   function Declaration_Hash (Value : Inventory) return Digest;
   function Count (Value : Inventory) return Natural;
   procedure Read_Entry (Value : Inventory; Position : Positive; Item : out Declaration; Status : out Outcome);
   -- Reobserves the control archive and, when conffiles exists, data payload under the caller's CAS
   -- reservation. Missing unflagged payloads remain explicit declarations, not
   -- invented empty files; remove-on-upgrade entries must be absent from data.
   -- Full payload attributes/link kinds survive. Interpretation of a symbolic
   -- link or a multiply linked inode is a separate namespace/configuration
   -- obligation, not permission to follow host paths or flatten their contents.
   -- Raw declarations, originals and payload objects remain in the existing CAS.
   -- Absent conffiles has hash zero; an explicitly empty file has its actual hash.
   -- Bounded names/count; invalid/unknown flags, unsafe paths and duplicates fail
   -- without exposing a partial inventory. No Unicode normalization or decoding.
private
   type Data;
   type Data_Access is access Data;
   type Inventory is new Ada.Finalization.Limited_Controlled with record
      State : Data_Access;
   end record;
   overriding procedure Finalize (Value : in out Inventory);
end Pkg_Deb_Conffiles;
