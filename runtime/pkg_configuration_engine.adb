-- SPDX-License-Identifier: BSD-3-Clause
package body Pkg_Configuration_Engine with SPARK_Mode=>Off is
   use type MC_Config_Receipt.Phase;
   procedure Guard(Root_ID,Transaction_ID : Identity;Plan,Evidence : Digest;
      Epoch,Fence : Counter;Phase : String;Status : out Outcome) is
      E : MC_Config_Receipt.Subject;A : MC_Config_Auth.Authority;C : MC_Config_Auth.Certificate;
      Now,Floor : Counter;R : MC_Config_Receipt.Receipt;
      Scope : MC_Config_Receipt.Phase;
   begin
      Status:=Denied;
      if Phase not in "prepare"|"capture"|"apply"|"commit"|"restore"|"file-effect"|
        "publish-file"|"finish-terminal"|"repair-journal" then return;end if;
      Scope:=Required_Scope(Phase);
      if (Phase in "prepare"|"capture"|"apply" and then Scope/=MC_Config_Receipt.Before_Apply) or else
         (Phase="commit" and then Scope/=MC_Config_Receipt.Accept_Running) or else
         (Phase="restore" and then Scope/=MC_Config_Receipt.Before_Restore) then return;end if;
      Authorize(Root_ID,Transaction_ID,Plan,Evidence,Epoch,Fence,Phase,Status);if Status/=OK then return;end if;
      Observe_Current(Root_ID,Transaction_ID,Plan,Phase,E,A,C,Now,Floor,Status);if Status/=OK then return;end if;
      if E.Root/=Root_ID or else E.Transaction/=Transaction_ID or else E.Plan/=Plan or else E.Epoch/=Epoch or else E.Scope/=Scope then Status:=Denied;return;end if;
      MC_Config_Auth.Verify(A,C,E,Now,Floor,R,Status);if Status/=OK then return;end if;
      Authorize(Root_ID,Transaction_ID,Plan,Evidence,Epoch,Fence,Phase,Status);
      -- No cross-system ACID assertion: actual per-file effects still use the
      -- underlying WAL and the held reservation. External root writers excluded.
   end Guard;
end Pkg_Configuration_Engine;
