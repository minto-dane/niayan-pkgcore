-- SPDX-License-Identifier: MIT
with MC_FS; with MC_Command; with MC_Text;
with Pkg_RPM; with Pkg_RPM_File;
package body Pkg_RPM_Auth with SPARK_Mode => Off is
   procedure Verify(T : MC_Tools.Tool; Private_Keyring : String;
      Store : MC_Store.Store; RPM_Digest : Digest; Deadline : Counter; Status : out Outcome) is
      F : MC_FS.File; Keyring : MC_FS.Root; Lock : MC_FS.File;
      Prefix : Pkg_RPM_File.Buffer; M : Pkg_RPM.Metadata;
      C : MC_Command.Invocation; R : MC_Command.Result; Actual : Digest; Size : Counter;
      procedure Add(S : String) is begin if Status=OK then MC_Tools.Set_Argument(C,S,Status); end if; end;
   begin
      MC_FS.Open_Root(Private_Keyring,Keyring,Status,Private_Only=>True); if Status/=OK then return; end if;
      MC_FS.Open_Locked(Keyring,"mission-verifier.lock",Lock,Status);
      if Status=OK then MC_Store.Open_Object(Store,RPM_Digest,F,Status); end if;
      if Status=OK then Pkg_RPM_File.Read_Headers(F,Prefix,M,Status); end if;
      if Status=OK and then (not M.Has_Signature_Tag or else M.Is_Source) then Status:=Denied; end if;
      Pkg_RPM_File.Free(Prefix);
      if Status=OK then
         Add("--dbpath"); Add(Private_Keyring); Add("--define"); Add("_pkgverify_level all");
         Add("--checksig"); Add("--"); Add("/proc/self/fd/4");
         C.Executable:=T.Path; C.Executable_Digest:=T.Content; C.Deadline:=Deadline;
         C.Pass_Descriptor:=MC_FS.Native(F); C.May_Have_External_Effects:=False;
         if Status=OK then MC_Command.Run(C,Bytes'(1..0=>0),R,Status); end if;
         if Status/=OK then Status:=Denied;
         else
            MC_FS.Hash(F,MC_Store.Max_Object_Size,Actual,Size,Status);
            if Status=OK and then Actual/=RPM_Digest then Status:=Conflict; end if;
         end if;
      end if;
      MC_FS.Close(F); MC_FS.Close(Lock); MC_FS.Close(Keyring);
   exception when others=>Pkg_RPM_File.Free(Prefix); MC_FS.Close(F); MC_FS.Close(Lock); MC_FS.Close(Keyring); Status:=IO_Error;
   end;
end Pkg_RPM_Auth;
