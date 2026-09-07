-- SPDX-License-Identifier: MIT
with MC_Types;use MC_Types;with MC_Config_Receipt;with MC_Config_Auth;with Pkg_File_Engine;
generic
   with procedure Authorize(Root_ID,Transaction_ID : Identity;Plan,Evidence : Digest;
      Epoch,Fence : Counter;Phase : String;Status : out Outcome);
   with function Required_Scope(Phase : String) return MC_Config_Receipt.Phase;
   with procedure Observe_Current(Root_ID,Transaction_ID : Identity;Plan : Digest;Phase : String;
      Expected : out MC_Config_Receipt.Subject;A : out MC_Config_Auth.Authority;
      C : out MC_Config_Auth.Certificate;Now,Floor : out Counter;Status : out Outcome);
package Pkg_Configuration_Engine with SPARK_Mode=>Off is
   procedure Guard(Root_ID,Transaction_ID : Identity;Plan,Evidence : Digest;
      Epoch,Fence : Counter;Phase : String;Status : out Outcome);
   package Engine is new Pkg_File_Engine(Guard);
   -- Compose Authorize with the original gate AND stop-barrier guard. This
   -- wrapper is opt-in: the legacy pkg_worker is not silently declared gated.
   -- Required_Scope comes from the protected operation context, NOT the certificate.
   -- Forward prepare/apply/capture must map to Before_Apply; commit to Accept_Running;
   -- restore to Before_Restore. file-effect/publish-file/finish-terminal inherit
   -- the serialized owning operation's mode. Unknown phases must not gain a permit.
   -- Observe_Current must independently re-read full effective source inventory,
   -- bind expected fields to the authenticated plan, check current boot/epoch,
   -- acquire the writer reservation and read the durable monotonic sequence floor.
   -- It must not copy Expected out of the untrusted certificate. No mock default.
end Pkg_Configuration_Engine;
