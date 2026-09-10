-- SPDX-License-Identifier: BSD-3-Clause
with MC_Contract_Profile;
package body Pkg_Quiescent_Engine with SPARK_Mode => Off is
   procedure Guard (Root_ID, Transaction_ID : Identity; Plan, Evidence : Digest;
      Epoch, Fence : Counter; Phase : String; Status : out Outcome)
   is
      P : MC_Stop_Barrier.Policy; S : MC_Stop_Barrier.State;
      Now : Counter; Boot : Identity; Found : Boolean := False;
   begin
      -- Unknown phases and permission changes are still decided by the original
      -- live authorization callback; a barrier is not a capability to mutate.
      Authorize (Root_ID,Transaction_ID,Plan,Evidence,Epoch,Fence,Phase,Status);
      if Status /= OK then return; end if;
      -- Recovery may concern a transaction from an older epoch. The observer
      -- returns the current authorized epoch; the original Authorize procedure
      -- must explicitly authorize recovery across epochs (never infer it here).
      Observe_Barrier (Root_ID,Transaction_ID,Plan,P,S,Now,Boot,Status);
      if Status /= OK then return; end if;
      Status := Denied;
      if P.Contract /= MC_Contract_Profile.Fingerprint or else P.Change_Plan /= Plan
        or else P.Epoch < Epoch or else P.Receiver_Boot /= Boot
        or else not MC_Stop_Barrier.Usable (P,S,Now) then return; end if;
      for I in 1..P.Count loop
         Found := Found or else P.Members (I).Resource_ID = Root_ID;
      end loop;
      if not Found then return; end if;
      -- Recheck live permission after the observation callback, which may have
      -- waited on a network. An external-resource fence is still required: this
      -- is not an atomic transaction spanning etcd and a filesystem.
      Authorize (Root_ID,Transaction_ID,Plan,Evidence,Epoch,Fence,Phase,Status);
   end Guard;
end Pkg_Quiescent_Engine;
