-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Finalization;
with MC_Types; use MC_Types;
with MC_Store; with Pkg_Conffile_Transition; with Pkg_Deb_Payload;
package Pkg_Conffile_Choice with SPARK_Mode => Off is
   type Operation is (Update, Remove, Purge);
   type Attribute_Source is (No_File, Local_Observation, Vendor_Payload);
   type File_Effect is record
      Path, Source_Path : Pkg_Deb_Payload.Byte_Strings.Bounded_String;
      Content : Digest := Zero_Digest;
      Source : Attribute_Source := No_File;
      Object, Permission_Override : Digest := Zero_Digest;
      Mode, UID, GID : Word := 0;
   end record;
   type Proposal is new Ada.Finalization.Limited_Controlled with private;
   procedure Prepare (Store : in out MC_Store.Store; Root_FD : Integer;
      Root_ID, Transaction : Identity; Context : Digest; Mode : Operation;
      Path : String; Prior_Original, Incoming_Original : Digest;
      Limit, Deadline : Counter; Value : in out Proposal; Status : out Outcome);
   function Address (Value : Proposal) return Digest;
   function Pending (Value : Proposal) return Pkg_Conffile_Transition.Decision;
   procedure Resolve (Store : in out MC_Store.Store; Value : in out Proposal;
      Expected : Digest; Selection : Pkg_Conffile_Transition.Choice;
      Backup_Path : String; Deadline : Counter;
      Decision, Closure : out Digest; Status : out Outcome);
   procedure Recheck (Store : MC_Store.Store; Value : in out Proposal;
      Decision, Closure : Digest; Deadline : Counter; Status : out Outcome);
   procedure Read_Effects (Store : MC_Store.Store; Value : in out Proposal;
      Decision, Closure : Digest; Deadline : Counter;
      Target, Backup : out File_Effect; Status : out Outcome);
   -- Rechecks before returning desired entries. No_File at Target.Path means
   -- desired absence; empty Backup.Path means no backup entry. Object is the
   -- full local observation or original vendor DEB, never a truncated attribute
   -- profile. Source_Path locates the source entry even for renamed backups.
   -- Vendor content inherits current regular-file mode/UID/GID when present;
   -- Permission_Override binds that local observation. Otherwise vendor numeric
   -- permissions are used. Local entries keep their observed permissions.
   -- NIACCH02 records these sources and numeric permissions. Remaining source
   -- attributes are retained, not silently defaulted; namespace/link identity,
   -- ACL/capability interactions and attribute application still need the full
   -- materialization/admission path. This is not a filesystem mutation API.
   procedure Clear (Value : in out Proposal);
   -- Internal content-choice planning, never an execution/consent authority.
   -- Prior_Original is the retained vendor baseline DEB (zero when untracked),
   -- not necessarily the currently selected package version. Both nonzero
   -- originals are reobserved; prior must declare this regular conffile. An
   -- incoming remove-on-upgrade flag determines the removal operation. Remove
   -- and Purge require a baseline and no incoming original. Ordinary-file
   -- conversions and links require separate effect handling and are refused.
   -- Context binds the enclosing intent, whose authenticity/root/catalog and
   -- ownership still require managed admission. Same Store stays open throughout.
   -- Resolve consumes this exact proposal once. A required choice cannot remain
   -- unresolved. A backup requires a caller-chosen distinct non-overlapping path
   -- observed absent; unnecessary backup paths are refused. No overwrite, pin,
   -- file application, baseline DB or alternative public command is introduced.
   -- The selection and exact deduplicated retained references are CAS objects.
   -- Recheck verifies those objects and live source/destination observations;
   -- failures clear the session and outputs. Orphan CAS objects can remain.
   -- Initial deadline is never extended. These optimistic snapshots retain the
   -- visibility/root-lifetime limits of Pkg_Conffile_Snapshot. Full attributes,
   -- global namespace conflicts, authenticated UI choice, durable recovery and
   -- generation closure/publication must be connected before applying effects.
private
   type Data;
   type Data_Access is access Data;
   type Proposal is new Ada.Finalization.Limited_Controlled with record
      State : Data_Access;
   end record;
   overriding procedure Finalize (Value : in out Proposal);
end Pkg_Conffile_Choice;
