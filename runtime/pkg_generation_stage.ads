-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
generic
   with procedure Authorize
     (Manifest, Plan, Evidence : Digest; Stage_ID, Transaction_ID : Identity;
      Epoch, Fence : Counter; Phase : String; Status : out Outcome);
package Pkg_Generation_Stage with SPARK_Mode => Off is
   procedure Provision
     (Root_Path, State_Path, Store_Path : String; Encoded_Manifest : Bytes;
      Expected_Manifest : Digest; Status : out Outcome);
   procedure Advance
     (Root_Path, State_Path, Store_Path : String; Expected_Manifest : Digest;
      Completed_Batches : out Natural; Status : out Outcome);
   procedure Inspect
     (Root_Path, State_Path, Store_Path : String; Expected_Manifest : Digest;
      Status : out Outcome);
   -- Isolated, unprivileged inactive-generation SDK. No CLI, active root switch,
   -- installed catalog writer, maintainer-script runner, or host-root permission.
   -- Provision accepts EMPTY private root/state dirs and an existing CAS only.
   -- Advance commits at most one PRIVATE batch or reconciles its recorded commit.
   -- Inspect checks every object, the exact entry count and all batch journals.
   -- Authorize is mandatory at each boundary (stage:* phases); it must maintain
   -- the same authenticated reservation and independently validate receipts,
   -- supply, effects, revocation, and the fact this generation remains INACTIVE.
   -- External privileged mutation is outside the filesystem model. The stage
   -- lock must be held by every cooperating staging/cleanup/publication path.
   -- OK from Inspect is physical evidence, NOT release/boot/execution authority.
   -- Missing/corrupt state is retained; no rebootstrap, repair, or blind retry.
end Pkg_Generation_Stage;
