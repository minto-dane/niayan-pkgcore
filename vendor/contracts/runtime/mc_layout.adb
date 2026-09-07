-- SPDX-License-Identifier: MIT
with MC_FS; with MC_Atomic; with MC_Properties; with MC_Paths;
package body MC_Layout with SPARK_Mode => Off is
   procedure Load(Policy_Directory : String; For_Packages : Boolean; L : out Layout; Status : out Outcome) is
      R : MC_FS.Root; B : Bytes(1..32_768); Used : Natural; D : MC_Properties.Document;
      procedure Get(K : String; V : out MC_Text.Value) is
      begin
         MC_Properties.Get(D,K,V,Status);
         if Status=OK then
            declare S : constant String:=MC_Text.Image(V); begin
               if S'Length<2 or else S(1)/='/' or else not MC_Paths.Safe_Relative(S(2..S'Last)) then Status:=Denied; end if;
            end;
         end if;
      end;
   begin
      L:=(others=><>); MC_FS.Open_Root(Policy_Directory,R,Status,Private_Only=>True); if Status/=OK then return; end if;
      MC_Atomic.Read(R,"paths.conf",B,Used,Status); MC_FS.Close(R); if Status/=OK then return; end if;
      MC_Properties.Parse(B(1..Used),D,Status); if Status/=OK then return; end if;
      if not MC_Properties.Has_Exactly(D,(if For_Packages then "root,state,store,ledger,spool" else "state,store,ledger,spool,binding"))
      then Status:=Invalid_Input; return; end if;
      Get("state",L.State); if Status/=OK then return; end if;
      Get("store",L.Store); if Status/=OK then return; end if;
      Get("ledger",L.Ledger); if Status/=OK then return; end if;
      Get("spool",L.Spool); if Status/=OK then return; end if;
      if For_Packages then Get("root",L.Root); else Get("binding",L.Binding); end if;
      -- Root '/' is intentionally not accepted by the deployment CLI. The library
      -- supports a held root descriptor, but a full-distribution adoption/migration
      -- must be qualified before replacing the host's package database writer.
   exception when others=>MC_FS.Close(R); Status:=IO_Error;
   end;
end MC_Layout;
