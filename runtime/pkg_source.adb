-- SPDX-License-Identifier: BSD-3-Clause
with MC_FS; with MC_Atomic; with MC_Properties; with MC_Text; with MC_Hex;
with MC_Authentic; with MC_Clock; with MC_HTTPS; with MC_Numbers; with MC_Codec; with MC_SHA256;
with Pkg_Artifact_Grant;
package body Pkg_Source with SPARK_Mode => Off is
   use type Wide; use type MC_FS.Entry_Kind;
   procedure Fetch(Policy_Directory, Trust_State_Directory : String; Signed_Grant : Bytes;
      Signature : MC_Signatures.Signature; Deadline : Counter;
      Store : in out MC_Store.Store; RPM_Object : out Digest; Status : out Outcome) is
      P,T : MC_FS.Root; Lock : MC_FS.File; Info : MC_FS.Entry_Info;
      B : Bytes(1..32_768); Used : Natural; D : MC_Properties.Document; V,Origin : MC_Text.Value;
      G : Pkg_Artifact_Grant.Grant; Key : MC_Signatures.Public_Key; Contract,Saved : Digest;
      Minimum,Now,Revision,Seen_Time : Counter; Frame : Bytes(1..128):=(others=>0);
   begin
      RPM_Object:=Zero_Digest; Pkg_Artifact_Grant.Decode(Signed_Grant,G,Status); if Status/=OK then return; end if;
      MC_FS.Open_Root(Policy_Directory,P,Status,Private_Only=>True); if Status/=OK then return; end if;
      MC_Atomic.Read(P,"repo-" & MC_Hex.Encode(G.Repository) & ".conf",B,Used,Status); MC_FS.Close(P);
      if Status/=OK then return; end if;
      MC_Properties.Parse(B(1..Used),D,Status); if Status/=OK then return; end if;
      if not MC_Properties.Has_Exactly(D,"key,origin,contract,min-revision") then Status:=Invalid_Input; return; end if;
      MC_Properties.Get(D,"key",V,Status); MC_Hex.Decode(MC_Text.Image(V),Key,Status); if Status/=OK then return; end if;
      MC_Properties.Get(D,"origin",Origin,Status);
      MC_Properties.Get(D,"contract",V,Status); MC_Hex.Decode(MC_Text.Image(V),Contract,Status); if Status/=OK then return; end if;
      MC_Properties.Get(D,"min-revision",V,Status); MC_Numbers.Parse(MC_Text.Image(V),Minimum,Status); if Status/=OK then return; end if;
      if Contract/=G.Contract or else G.Revision<Minimum then Status:=Denied; return; end if;
      MC_Authentic.Verify("MC-ARTIFACT-v2",Signed_Grant,Signature,Key,Status); if Status/=OK then return; end if;
      MC_Clock.Realtime_Seconds(Now,Status); if Status/=OK then return; end if;
      if Now<G.Issued or else Now>=G.Expires then Status:=Stale; return; end if;
      MC_FS.Open_Root(Trust_State_Directory,T,Status,Private_Only=>True); if Status/=OK then return; end if;
      MC_FS.Open_Locked(T,"repository.lock",Lock,Status); if Status/=OK then MC_FS.Close(T); return; end if;
      declare Name : constant String:="repo-" & MC_Hex.Encode(G.Repository) & ".state"; begin
         MC_FS.Stat(T,Name,Info,Status);
         if Status=OK and then Info.Kind/=MC_FS.Absent then
            MC_Atomic.Read(T,Name,Frame,Used,Status);
            if Status=OK and then (Used/=128 or else Frame(1..16)/=G.Repository
              or else Frame(97..128)/=MC_SHA256.Hash(Frame(1..96)) or else not Is_Zero(Frame(65..96))
              or else MC_Codec.U64(Frame,17)>Wide(Counter'Last) or else MC_Codec.U64(Frame,57)>Wide(Counter'Last))
            then Status:=Corrupt; end if;
            if Status=OK then
               Revision:=Counter(MC_Codec.U64(Frame,17)); Seen_Time:=Counter(MC_Codec.U64(Frame,57));
               if G.Revision<Revision or else Now<Seen_Time or else (G.Revision=Revision and then Frame(25..56)/=G.Snapshot)
               then Status:=Stale; end if;
            end if;
         end if;
         if Status=OK then
            Frame:=(others=>0); Frame(1..16):=G.Repository; MC_Codec.Put64(Frame,17,Wide(G.Revision));
            Frame(25..56):=G.Snapshot; MC_Codec.Put64(Frame,57,Wide(Now)); Frame(97..128):=MC_SHA256.Hash(Frame(1..96));
            MC_Atomic.Write(T,Name,Frame,False,Status);
         end if;
      end;
      MC_FS.Close(Lock); MC_FS.Close(T); if Status/=OK then return; end if;
      -- This only freezes accepted revision; a failed download never triggers rollback.
      MC_Store.Put(Store,Signed_Grant,Saved,Status); if Status/=OK then return; end if;
      MC_Store.Put(Store,Signature,Saved,Status); if Status/=OK then return; end if;
      MC_HTTPS.Fetch(MC_Text.Image(G.URL),MC_Text.Image(Origin),G.Object,G.Size,Deadline,Store,Status);
      if Status=OK then RPM_Object:=G.Object; end if;
   exception when others=>MC_FS.Close(P); MC_FS.Close(Lock); MC_FS.Close(T); Status:=IO_Error;
   end;
end Pkg_Source;
