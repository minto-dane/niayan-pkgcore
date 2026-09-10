-- SPDX-License-Identifier: BSD-3-Clause
with Pkg_Quiescent_Engine; with Pkg_Configuration_Engine; with Pkg_Resolution_Engine;
package body Pkg_Managed_Engine with SPARK_Mode => Off is
   package Stopped is new Pkg_Quiescent_Engine(Authorize,Observe_Barrier);
   package Configured is new Pkg_Configuration_Engine(Stopped.Guard,Required_Scope,Observe_Configuration);
   package Resolved is new Pkg_Resolution_Engine(Configured.Guard,Observe_Resolution,
                                                Check_Native,Recheck_Current);
   procedure Guard (Root_ID,Transaction_ID : Identity; Plan,Evidence : Digest;
      Epoch,Fence : Counter; Phase : String; Status : out Outcome) is
   begin
      Resolved.Guard(Root_ID,Transaction_ID,Plan,Evidence,Epoch,Fence,Phase,Status);
   exception when others => Status:=Indeterminate;
   end Guard;
end Pkg_Managed_Engine;
