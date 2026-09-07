-- SPDX-License-Identifier: MIT
with MC_FS; with MC_Atomic; with MC_Properties; with MC_Text; with MC_Hex; with MC_Numbers;
with MC_SHA256; with Pkg_File_Plan; with Ada.Unchecked_Deallocation;
package body Pkg_Plan_Compiler with SPARK_Mode=>Off is
   procedure Compile(Manifest_Directory, Output_Directory : String; Plan_Digest : out Digest; Status : out Outcome) is
      R,O : MC_FS.Root; D : MC_Properties.Document; T : MC_Text.Value; N : Counter;
      B : Bytes(1..262_144); Used : Natural;
      type Plan_Access is access Pkg_File_Plan.Plan; P : Plan_Access:=null;
      type Buffer_Access is access Bytes; Encoded : Buffer_Access:=null;
      procedure Free is new Ada.Unchecked_Deallocation(Pkg_File_Plan.Plan,Plan_Access);
      procedure Free is new Ada.Unchecked_Deallocation(Bytes,Buffer_Access);
      procedure Done is begin MC_FS.Close(R); MC_FS.Close(O); if P/=null then Free(P); end if; if Encoded/=null then Free(Encoded); end if; end;
      procedure Load(Name,Keys : String) is
      begin
         if Status/=OK then return; end if;
         MC_Atomic.Read(R,Name,B,Used,Status);
         if Status=OK then MC_Properties.Parse(B(1..Used),D,Status); end if;
         if Status=OK and then not MC_Properties.Has_Exactly(D,Keys) then Status:=Invalid_Input; end if;
      end;
      procedure Field(K : String; V : out Bytes) is
      begin
         V:=(others=>0); if Status/=OK then return; end if;
         MC_Properties.Get(D,K,T,Status); if Status=OK then MC_Hex.Decode(MC_Text.Image(T),V,Status); end if;
      end;
      procedure Number(K : String; V : out Counter) is
      begin
         V:=0; if Status/=OK then return; end if;
         MC_Properties.Get(D,K,T,Status); if Status=OK then MC_Numbers.Parse(MC_Text.Image(T),V,Status); end if;
      end;
      procedure Word_Field(K : String; V : out Word) is
         X : Counter;
      begin Number(K,X); if X>Counter(Word'Last) then Status:=Invalid_Input; else V:=Word(X); end if; end;
      procedure Shape(Prefix : String; V : out Pkg_File_Plan.Shape) is
      begin
         V:=(others=><>); if Status/=OK then return; end if;
         MC_Properties.Get(D,Prefix & "kind",T,Status); if Status/=OK then return; end if;
         if MC_Text.Image(T)="absent" then V.Node_Kind:=Pkg_File_Plan.Absent;
         elsif MC_Text.Image(T)="regular" then V.Node_Kind:=Pkg_File_Plan.Regular;
         elsif MC_Text.Image(T)="directory" then V.Node_Kind:=Pkg_File_Plan.Directory;
         elsif MC_Text.Image(T)="symlink" then V.Node_Kind:=Pkg_File_Plan.Symbolic_Link;
         else Status:=Unsupported; return; end if;
         Word_Field(Prefix & "mode",V.Mode); Word_Field(Prefix & "uid",V.UID); Word_Field(Prefix & "gid",V.GID);
         Number(Prefix & "size",V.Size); Number(Prefix & "mtime",V.Mtime_Sec); Number(Prefix & "nsec",N);
         if N>999_999_999 then Status:=Invalid_Input; else V.Mtime_Nsec:=Natural(N); end if;
         Field(Prefix & "content",V.Content); Field(Prefix & "xattrs",V.Xattrs);
         if Status=OK and then not Pkg_File_Plan.Valid(V) then Status:=Invalid_Input; end if;
      end;
   begin
      Plan_Digest:=Zero_Digest;
      MC_FS.Open_Root(Manifest_Directory,R,Status,Private_Only=>True); if Status/=OK then Done; return; end if;
      MC_FS.Open_Root(Output_Directory,O,Status,Private_Only=>True); if Status/=OK then Done; return; end if;
      P:=new Pkg_File_Plan.Plan;
      Load("plan.conf","root,transaction,base,target,epoch,fence,package-set,effect-contract,count");
      Field("root",P.Root_ID); Field("transaction",P.Transaction_ID); Number("base",P.Base_Generation);
      Number("target",P.Target_Generation); Number("epoch",P.Epoch); Number("fence",P.Fence);
      Field("package-set",P.Package_Set); Field("effect-contract",P.Effect_Contract); Number("count",N);
      if Status/=OK or else N=0 or else N>Pkg_File_Plan.Max_Changes then Status:=Invalid_Input; Done; return; end if; P.Count:=Natural(N);
      for I in 1..P.Count loop
         Load("change-" & MC_Numbers.Image(Counter(I)) & ".conf",
           "path,domain,before-kind,before-mode,before-uid,before-gid,before-size,before-mtime,before-nsec,before-content,before-xattrs," &
           "after-kind,after-mode,after-uid,after-gid,after-size,after-mtime,after-nsec,after-content,after-xattrs");
         if Status/=OK then Done; return; end if;
         MC_Properties.Get(D,"path",P.Changes(I).Path,Status); if Status/=OK then Done; return; end if;
         MC_Properties.Get(D,"domain",T,Status); if Status/=OK then Done; return; end if;
         if MC_Text.Image(T)="packaged" then P.Changes(I).Domain:=Pkg_File_Plan.Packaged_Files;
         elsif MC_Text.Image(T)="configuration" then P.Changes(I).Domain:=Pkg_File_Plan.Managed_Configuration;
         else Status:=Denied; Done; return; end if;
         Shape("before-",P.Changes(I).Before); Shape("after-",P.Changes(I).After);
         if Status/=OK then Done; return; end if;
      end loop;
      Encoded:=new Bytes(1..Pkg_File_Plan.Max_Plan_Bytes);
      Pkg_File_Plan.Encode(P.all,Encoded.all,Used,Status);
      if Status=OK then Plan_Digest:=MC_SHA256.Hash(Encoded(1..Used)); MC_Atomic.Write(O,"plan.bin",Encoded(1..Used),True,Status); end if;
      Done;
   exception when others=>Done; Status:=Indeterminate;
   end;
end Pkg_Plan_Compiler;
