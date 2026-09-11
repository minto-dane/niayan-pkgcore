-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_FS; with MC_Store; with Pkg_Root_Preparation; with Pkg_Generation_Configuration;
generic
   with procedure Authorize
     (Manifest, Plan, Evidence : Digest; Stage_ID, Transaction_ID : Identity;
      Epoch, Fence : Counter; Phase : String; Status : out Outcome);
   with procedure Observe_Configuration (Generation : Digest; Root_ID, Transaction_ID : Identity;
      Context : Digest; Phase : String; Root_FD : out Integer; Status : out Outcome)
      is Pkg_Generation_Configuration.Unavailable;
package Pkg_Generation_Stage with SPARK_Mode => Off is
   type Verified_Generation is limited private;
   type Retained_Generation is limited private;
   procedure Verify_Retained_And_Hold
     (Root_Path, State_Path, Store_Path : String; Expected_Manifest : Digest;
      C : in out Retained_Generation; Deadline : Counter; Status : out Outcome);
   function Retained_Held (C : Retained_Generation) return Boolean;
   function Retained_Manifest (C : Retained_Generation) return Digest;
   procedure Close (C : in out Retained_Generation);
   -- Read-only physical stage, journals, pins and saved native retention. This
   -- DISTINCT type does not establish current configuration and cannot be used
   -- as a Verified_Generation. The inspect-retained/inspect-retained-batch/
   -- inspected-retained authorizations remain mandatory. No source observation
   -- is revived. A caller must prove its exact already-accepted publication
   -- state and journal before using this evidence for terminal reconciliation;
   -- it is never sufficient for new/in-flight publication, extraction or boot.

   procedure Verify_And_Hold
     (Root_Path, State_Path, Store_Path : String; Expected_Manifest : Digest;
      C : in out Verified_Generation; Deadline : Counter; Status : out Outcome);
   function Held (C : Verified_Generation) return Boolean;
   function Manifest (C : Verified_Generation) return Digest;
   procedure Close (C : in out Verified_Generation);
   -- Holds BOTH generation and root reservations after full inspection, until
   -- Close. The CAS lock is released for the publication engine to acquire it.
   -- Holding this object is physical exclusion, not a signed execution permit.
   procedure Provision
     (Root_Path, State_Path, Store_Path : String; Encoded_Manifest : Bytes;
      Expected_Manifest : Digest; Deadline : Counter; Status : out Outcome);
   procedure Advance
     (Root_Path, State_Path, Store_Path : String; Expected_Manifest : Digest;
      Completed_Batches : out Natural; Deadline : Counter; Status : out Outcome);
   type Reinspected_Generation is limited private;
   generic
      with procedure Observe_Root
        (Generation : Digest; Stage_ID : Identity; Phase : String;
         Original_Deadline : out Counter; Root : out Pkg_Root_Preparation.Root_Identity;
         Status : out Outcome);
   procedure Reinspect_Root_And_Hold
     (Root_Path, State_Path, Store_Path, Socket_Path : String;
      Expected_Manifest, Expected_Worker : Digest; C : in out Reinspected_Generation;
      Deadline : Counter; Status : out Outcome);
   function Held (C : Reinspected_Generation) return Boolean;
   function Root_Observation (C : Reinspected_Generation) return Pkg_Root_Preparation.Root_Identity;
   procedure Close (C : in out Reinspected_Generation);
   -- A distinct observation handle holds generation/root/CAS reservations and
   -- the archive FD until Close, including after its deadline expires. Held
   -- and Root_Observation stop exposing success at expiry. No implicit thaw.
   -- Observe_Root is mandatory and independent of the service response. It
   -- authenticates the saved extraction deadline and frozen mount identity,
   -- and retains bank/all-writer/mount exclusion for the WHOLE handle lifetime.
   -- The provider is borrowed: its owner releases it only after Close. Neither
   -- this SDK nor a read-only view alone establishes global quiescence. This
   -- type cannot be passed to logical publication or treated as boot authority.
   procedure Prepare_Root
     (Root_Path, State_Path, Store_Path, Socket_Path : String;
      Expected_Manifest, Expected_Worker : Digest; Deadline : Counter; Status : out Outcome);
   -- v5/v6. Hold stage/root/CAS reservations through the actual FD request and
   -- final content/admission rechecks. prepare-root/root-prepared authorization
   -- phases are mandatory; a service response alone never grants publication.
   -- Failure after delivery is uncertain: no implicit retry or tree reuse.
   procedure Inspect
     (Root_Path, State_Path, Store_Path : String; Expected_Manifest : Digest; Deadline : Counter;
      Status : out Outcome);
   -- v6 requires an independently authenticated, borrowed configuration source
   -- root via Observe_Configuration; its default refuses live v6 operations.
   -- The provider retains source exclusion through each whole operation. Saved
   -- choices are freshly verified after every CAS reacquisition, including the
   -- inner batch engine's Check_Inputs before prepare/resume. Physical request
   -- and response boundaries recheck them too. This is inactive staging only;
   -- source changes or mount identity migration require a new admitted selection.
   -- Accepted publication recovery cannot reuse this before-state check.
   -- Every operation requires a finite boottime deadline. v2 checks the pinned
   -- catalog closure under the store reservation; v1 remains structural staging.
   -- Clock checks also surround mandatory authorization and private batch gates.
   -- Isolated, unprivileged inactive-generation SDK. No CLI, active root switch,
   -- installed catalog writer, maintainer-script runner, or host-root permission.
   -- Provision accepts EMPTY private root/state dirs and an existing CAS only.
   -- Advance commits at most one PRIVATE batch or reconciles its recorded commit.
   -- Inspect checks every object, the exact entry count and all batch journals.
   -- Authorize is mandatory at each boundary (stage:* phases); it must maintain
   -- the same authenticated reservation and independently validate receipts,
   -- supply, effects, revocation, and INACTIVE status for every mutation.
   -- Inspection of an accepted generation for publication reconciliation is
   -- read-only and still requires the same authenticated reservation.
   -- External privileged mutation is outside the filesystem model. The stage
   -- lock must be held by every cooperating staging/cleanup/publication path.
   -- OK from Inspect is physical evidence, NOT release/boot/execution authority.
   -- Missing/corrupt state is retained; no rebootstrap, repair, or blind retry.
private
   type Verified_Generation is limited record
      Root, State : MC_FS.Root;
      Lock, Root_Lock : MC_FS.File;
      Verified : Boolean := False;
      Bound_Manifest : Digest := Zero_Digest;
   end record;
   type Retained_Generation is limited record
      Saved : Verified_Generation;
   end record;
   type Reinspected_Generation is limited record
      Stage : Verified_Generation;
      Store : MC_Store.Store;
      Archive : MC_FS.File;
      Physical : Pkg_Root_Preparation.Root_Identity;
      Deadline : Counter := 0;
      Verified : Boolean := False;
   end record;
end Pkg_Generation_Stage;
