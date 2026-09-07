-- SPDX-License-Identifier: MIT
with Ada.Unchecked_Deallocation;
package body Pkg_RPM_File with SPARK_Mode => Off is
   procedure Release is new Ada.Unchecked_Deallocation(Bytes,Buffer);
   procedure Read_Headers(F : MC_FS.File; Data : out Buffer; M : out Pkg_RPM.Metadata; Status : out Outcome) is
      V : MC_FS.Entry_Info; Size, At_Byte, N, Got : Natural;
   begin
      Data:=null; M:=(others=><>); MC_FS.Info(F,V,Status); if Status/=OK then return; end if;
      -- Two 16 MiB header stores plus indices fit in this prefix. Large RPM
      -- payloads are not loaded into memory; archive decoding streams separately.
      Size:=Natural(Counter'Min(V.Size,34*1024*1024));
      Data:=new Bytes(1..Size); At_Byte:=0;
      while At_Byte<Size loop
         N:=Natural'Min(65_536,Size-At_Byte);
         MC_FS.Read_At(F,Counter(At_Byte),Data(At_Byte+1..At_Byte+N),Got,Status);
         if Status/=OK or else Got/=N then Free(Data); Status:=IO_Error; return; end if;
         At_Byte:=At_Byte+N;
      end loop;
      Pkg_RPM.Inspect(Data.all,M,Status);
      if Status/=OK then Free(Data); end if;
   exception when others => Free(Data); Status:=IO_Error;
   end;
   procedure Free(Data : in out Buffer) is begin if Data/=null then Release(Data); end if; end;
end Pkg_RPM_File;
