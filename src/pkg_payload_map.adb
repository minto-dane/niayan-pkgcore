-- SPDX-License-Identifier: MIT
with Pkg_RPM_Fields; with MC_Hex; with MC_SHA256; with MC_Paths;
package body Pkg_Payload_Map with SPARK_Mode is
   use Pkg_RPM_Fields; use Pkg_File_Plan;
   use type Word; use type Wide;
   function Find(Files : Inventory; Path : String) return Natural is
   begin
      for I in 1..Files.Count loop if MC_Text.Image(Files.Files(I).Path)=Path then return I; end if; end loop;
      return 0;
   end;
   procedure Decode(B : Bytes; M : Pkg_RPM.Metadata; Files : out Inventory; Status : out Outcome) is
      N : Natural:=Count(M,1117); V, Index, Digest_Algorithm : Wide;
      Directory_Name, Base_Name, Hash_Text : MC_Text.Value;
      Size_Tag : Word:=1028;
   begin
      Files:=(others=><>); Status:=Unsupported;
      if M.Is_Source or else N>Capacity then return; end if;
      if Count(M,5008)>0 then Size_Tag:=5008; end if;
      if N=0 then Status:=OK; return; end if;
      if Count(M,1030)/=N or else Count(M,1116)/=N or else Count(M,Size_Tag)/=N
        or else Count(M,1037)/=N or else Count(M,1039)/=N or else Count(M,1040)/=N
        or else Count(M,1035)/=N or else Count(M,1036)/=N then return; end if;
      Number(B,M,5011,1,Digest_Algorithm,Status);
      if Status/=OK or else Digest_Algorithm/=8 then Status:=Unsupported; return; end if;
      Files.Count:=N;
      for I in 1..N loop
         Text(B,M,1117,I,Base_Name,Status); if Status/=OK then return; end if;
         Number(B,M,1116,I,Index,Status); if Status/=OK or else Index>=Wide(Count(M,1118)) then Status:=Corrupt; return; end if;
         Text(B,M,1118,Positive(Index+1),Directory_Name,Status); if Status/=OK then return; end if;
         declare D : constant String:=MC_Text.Image(Directory_Name); P : constant String:=MC_Text.Image(Base_Name); begin
            if D'Length=0 or else D(D'First)/='/' or else D(D'Last)/='/' or else not MC_Paths.Safe_Component(P)
            then Status:=Unsupported; return; end if;
            MC_Text.Set(Files.Files(I).Path,D(D'First+1..D'Last)&P,Status); if Status/=OK then return; end if;
            if not MC_Paths.Safe_Relative(MC_Text.Image(Files.Files(I).Path)) then Status:=Unsupported; return; end if;
         end;
         for J in 1..I-1 loop if MC_Text.Equal(Files.Files(I).Path,Files.Files(J).Path) then Status:=Corrupt; return; end if; end loop;
         Number(B,M,1030,I,V,Status); if Status/=OK or else V>65_535 then Status:=Corrupt; return; end if;
         Files.Files(I).Mode:=Word(V) and 8#7777#;
         case Word(V) and 8#170000# is
            when 8#100000# => Files.Files(I).Kind:=Regular;
            when 8#040000# => Files.Files(I).Kind:=Directory;
            when 8#120000# => Files.Files(I).Kind:=Symbolic_Link;
            when others => Status:=Unsupported; return;
         end case;
         Number(B,M,Size_Tag,I,V,Status); if Status/=OK or else V>8*1024*1024*1024 then Status:=Exhausted; return; end if;
         Files.Files(I).Size:=Counter(V);
         Number(B,M,1037,I,V,Status); if Status/=OK or else V>Wide(Word'Last) then Status:=Corrupt; return; end if;
         Files.Files(I).Flags:=Word(V); Files.Files(I).Ghost:=(Word(V) and 64)/=0;
         Text(B,M,1039,I,Files.Files(I).User_Name,Status); if Status/=OK then return; end if;
         Text(B,M,1040,I,Files.Files(I).Group_Name,Status); if Status/=OK then return; end if;
         if Files.Files(I).Kind=Regular and then not Files.Files(I).Ghost then
            Text(B,M,1035,I,Hash_Text,Status); if Status/=OK then return; end if;
            MC_Hex.Decode(MC_Text.Image(Hash_Text),Files.Files(I).Content,Status); if Status/=OK then return; end if;
         elsif Files.Files(I).Kind=Symbolic_Link then
            Text(B,M,1036,I,Files.Files(I).Link_Target,Status); if Status/=OK then return; end if;
            declare L : constant String:=MC_Text.Image(Files.Files(I).Link_Target); Data : Bytes(1..L'Length); begin
               if L'Length=0 then Status:=Corrupt; return; end if;
               for J in L'Range loop Data(J):=Byte(Character'Pos(L(J))); end loop;
               Files.Files(I).Content:=MC_SHA256.Hash(Data); Files.Files(I).Size:=Counter(L'Length);
            end;
         end if;
      end loop;
      Status:=OK;
   end;
end Pkg_Payload_Map;
