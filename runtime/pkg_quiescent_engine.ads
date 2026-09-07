-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types; with MC_Stop_Barrier; with Pkg_File_Engine;
generic
   with procedure Authorize (Root_ID, Transaction_ID : Identity; Plan, Evidence : Digest;
      Epoch, Fence : Counter; Phase : String; Status : out Outcome);
   with procedure Observe_Barrier (Root_ID, Transaction_ID : Identity; Plan : Digest;
      P : out MC_Stop_Barrier.Policy; S : out MC_Stop_Barrier.State;
      Now : out Counter; Receiver_Boot : out Identity; Status : out Outcome);
package Pkg_Quiescent_Engine with SPARK_Mode => Off is
   procedure Guard (Root_ID, Transaction_ID : Identity; Plan, Evidence : Digest;
      Epoch, Fence : Counter; Phase : String; Status : out Outcome);
   package Engine is new Pkg_File_Engine (Guard);
   -- Opt-in stricter execution path: all underlying engine authorization points
   -- also require a fresh, authenticated stop barrier for this exact plan+root.
   -- Observe_Barrier must load the authoritative latest barrier AND current held
   -- gate (linearizable/anti-rollback), not replay a previously sealed file.
   -- A new barrier is required if observations expire during a long operation.
   -- The current barrier may use a newer epoch during recovery of an old
   -- transaction, but Authorize must independently permit that recovery.
   -- Original per-file journaling/recovery and host-root restrictions remain.
end Pkg_Quiescent_Engine;
