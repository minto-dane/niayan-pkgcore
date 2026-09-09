-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with MC_FS;
generic
   with procedure Authorize
     (Manifest, Plan, Evidence : Digest; Stage_ID, Transaction_ID : Identity;
      Epoch, Fence : Counter; Phase : String; Status : out Outcome);
package Pkg_Generation_Stage with SPARK_Mode => Off is
   type Verified_Generation is limited private;
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
   procedure Inspect
     (Root_Path, State_Path, Store_Path : String; Expected_Manifest : Digest; Deadline : Counter;
      Status : out Outcome);
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
end Pkg_Generation_Stage;
