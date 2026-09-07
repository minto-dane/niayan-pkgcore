-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with MC_FS; with MC_Store; with MC_Log;
with Pkg_File_Plan; with Pkg_Root_State;
generic
   -- A site adapter MUST revalidate current ownership, local boot-bound lease,
   -- authenticated request, revocation and external quiescence at every call.
   -- No network-supplied booleans are accepted by this engine.
   with procedure Authorize(Root_ID, Transaction_ID : Identity; Plan, Evidence : Digest;
      Epoch, Fence : Counter; Phase : String; Status : out Outcome);
package Pkg_File_Engine with SPARK_Mode => Off is
   type Context is limited private;
   type Actual_Image is (All_Before, All_After, Mixed_Known, Unknown_Objects);
   procedure Provision(Root_Path, State_Path : String; Root_ID : Identity; Status : out Outcome);
   procedure Open(Root_Path, State_Path, Store_Path : String; Root_ID : Identity;
                  C : in out Context; Status : out Outcome);
   procedure Prepare(C : in out Context; Encoded_Plan : Bytes;
                     Expected_Digest : Digest; Status : out Outcome);
   procedure Resume(C : in out Context; Status : out Outcome);
   procedure Resume_Recorded(C : in out Context; Expected_Plan : Digest; Status : out Outcome);
   function Loaded_Plan(C : Context) return Digest;
   procedure Inspect(C : in out Context; Image : out Actual_Image; Status : out Outcome);
   procedure Apply(C : in out Context; Status : out Outcome);
   procedure Commit(C : in out Context; Health_Receipt : Digest; Status : out Outcome);
   procedure Restore(C : in out Context; Compatibility_Receipt : Digest; Status : out Outcome);
   procedure Reconcile_Terminal(C : in out Context; Status : out Outcome);
   procedure Repair_Torn_Journal(C : in out Context; Status : out Outcome);
   function Generation(C : Context) return Counter;
   function Accepted_Plan(C : Context) return Digest;
   function Has_Active_Change(C : Context) return Boolean;
   procedure Close(C : in out Context);
   -- Real fd-relative file/CAS/WAL execution. Not an all-RPM distro replacement.
   -- Unknown pre/post images are quarantined, never overwritten. Restoration only
   -- touches listed packaged/config paths and requires an external compatibility grant.
   -- Only one process may own Context. Any Indeterminate outcome requires close,
   -- reopen and inspection; it must not be retried on the same live Context.
private
   type Plan_Access is access Pkg_File_Plan.Plan;
   type Context is limited record
      Root, State_Directory : MC_FS.Root;
      Root_Lock : MC_FS.File;
      Store : MC_Store.Store;
      Journal : MC_Log.Journal;
      Root_State : Pkg_Root_State.State;
      Plan : Plan_Access := null;
      Plan_Digest : Digest := Zero_Digest;
      Opened, Poisoned : Boolean := False;
   end record;
end Pkg_File_Engine;
