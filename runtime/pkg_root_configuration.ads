-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Finalization;
with MC_Types; use MC_Types;
with MC_Store; with Pkg_Conffile_Choice; with Pkg_Deb_Payload;
package Pkg_Root_Configuration with SPARK_Mode => Off is
   Max_Choices : constant := 4_096;
   type Proposal_Access is access all Pkg_Conffile_Choice.Proposal;
   type Choice_Reference is record
      Value : Proposal_Access;
      Decision, Closure : Digest := Zero_Digest;
   end record;
   type Choices is array (Positive range <>) of Choice_Reference;
   type Layout is new Ada.Finalization.Limited_Controlled with private;
   type Input_Binding is record
      Manifest, Catalog, Closure, Archive, Ownership : Digest := Zero_Digest;
      Root_ID, Transaction : Identity := Zero_Identity;
      Context : Digest := Zero_Digest;
   end record;
   type Entry_Reference is record
      Path : Pkg_Deb_Payload.Byte_Strings.Bounded_String;
      Base_Claim : Natural := 0;
      Configuration : Pkg_Conffile_Choice.File_Effect;
      Decision, Retained_Closure : Digest := Zero_Digest;
   end record;
   type Choice_Binding is record
      Path : Pkg_Deb_Payload.Byte_Strings.Bounded_String;
      Proposal, Decision, Closure : Digest := Zero_Digest;
   end record;
   procedure Prepare (Store : in out MC_Store.Store; Manifest, Catalog, Closure : Digest;
      Root_ID, Transaction : Identity; Context : Digest; Native_Architecture : String;
      Selected : Choices; Limit, Deadline : Counter; Value : in out Layout; Status : out Outcome);
   procedure Clear (Value : in out Layout);
   function Count (Value : Layout) return Natural;
   function Binding (Value : Layout) return Input_Binding;
   procedure Read_Entry (Value : Layout; Position : Positive; Item : out Entry_Reference; Status : out Outcome);
   function Choice_Count (Value : Layout) return Natural;
   procedure Read_Choice (Value : Layout; Position : Positive; Item : out Choice_Binding; Status : out Outcome);
   -- A complete path-ordered projection of a verified NIAROOT1/2 plus live
   -- configuration decisions. Each entry uses either its exact base claim or
   -- the full configuration effect. Deleted targets are absent, not empty files.
   -- Choice scopes must match, incoming originals must belong to the catalog,
   -- and all incoming conffile declarations need a matching choice. Backups may
   -- not take any base claim or another configuration path. Parents must survive
   -- as directories. Hardlink dependencies crossing a replaced target require
   -- a separate inode-effects plan and are refused, not silently retargeted.
   -- Caller-supplied root/context assertions still need managed admission.
   -- This projection does not serialize a configured tar, freeze filesystems,
   -- authenticate consent, or authorize extraction/publication. No new DB.
   -- Read_Entry is a snapshot of this preparation, not a live recheck; the caller
   -- must prepare/recheck the original choices before using it for execution.
   -- Choice references are borrowed for Prepare only; callers own the proposals
   -- and must keep them alive throughout that call. Binding retains the exact
   -- base identities; configured entries retain their decision/closure hashes.
   -- Read_Choice retains every decision in supplied order, including choices
   -- which leave no file. These references still require generation retention.
private
   type Data;
   type Data_Access is access Data;
   type Layout is new Ada.Finalization.Limited_Controlled with record
      State : Data_Access;
   end record;
   overriding procedure Finalize (Value : in out Layout);
end Pkg_Root_Configuration;
