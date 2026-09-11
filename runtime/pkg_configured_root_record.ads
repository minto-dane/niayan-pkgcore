-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Finalization;
with MC_Types; use MC_Types;
with MC_Store; with Pkg_Root_Configuration; with Pkg_Catalog_Retention;
package Pkg_Configured_Root_Record with SPARK_Mode => Off is
   Header_Size : constant := 320;
   Retention_Header_Size : constant := 48;
   Max_Objects : constant := Pkg_Catalog_Retention.Max_Objects +
      40 * Pkg_Root_Configuration.Max_Choices + 8;
   Max_Configurations : constant := 2 * Pkg_Root_Configuration.Max_Choices;
   Max_Manifest_Bytes : constant := Header_Size +
      96 * Pkg_Root_Configuration.Max_Choices + 80 * Max_Configurations;
   type Root_Binding is record
      Base : Pkg_Root_Configuration.Input_Binding;
      Architecture, Archive : Digest := Zero_Digest;
      Size, Entries : Counter := 0;
   end record;
   type Saved_Choice is record
      Proposal, Decision, Closure : Digest := Zero_Digest;
   end record;
   type Saved_Configuration is record
      Position : Natural := 0;
      Prefix, Content : Digest := Zero_Digest;
      Size : Counter := 0;
   end record;
   type View is new Ada.Finalization.Limited_Controlled with private;
   procedure Load (Store : MC_Store.Store; Manifest, Retained : Digest;
      Limit, Deadline : Counter; Value : in out View; Status : out Outcome);
   procedure Clear (Value : in out View);
   function Binding (Value : View) return Root_Binding;
   function Choice_Count (Value : View) return Natural;
   function Configuration_Count (Value : View) return Natural;
   function Object_Count (Value : View) return Natural;
   procedure Read_Choice (Value : View; Position : Positive;
      Item : out Saved_Choice; Status : out Outcome);
   procedure Read_Configuration (Value : View; Position : Positive;
      Item : out Saved_Configuration; Status : out Outcome);
   procedure Read_Object (Value : View; Position : Positive;
      Item : out Digest; Status : out Outcome);
   -- Read-only NIACRT01/NIACRC01 inspection, with no proposal session or live
   -- filesystem observation. Checks bounded framing, nested record identities,
   -- root/catalog/choice scope, archive/content sizes, strictly ordered rows and
   -- the exact union declared by catalog/choice closures plus generated objects.
   -- Every member is opened and hashed, and consumed records are hashed/stat
   -- checked again. No missing object is reconstructed and no CAS write occurs.
   -- Object enumeration is the NIACRC01 member list (includes Manifest, excludes
   -- Retained itself); a future outer generation root must retain both records.
   -- This is saved-reference integrity, NOT source-derived closure completeness,
   -- ownership/layout validation, consent, current-state validity or GC authority.
   -- The caller must authenticate the expected record digests and bind the
   -- returned identities to its generation. Old proposal deadlines are historical
   -- data, never renewed execution permission. Load uses a new finite deadline.
   -- Live Pkg_Configured_Root.Verify remains required before use for execution.
   -- Same store reservation and ordinary UID required; failure clears the view.
private
   type Data;
   type Data_Access is access Data;
   type View is new Ada.Finalization.Limited_Controlled with record
      State : Data_Access;
   end record;
   overriding procedure Finalize (Value : in out View);
end Pkg_Configured_Root_Record;
