-- SPDX-License-Identifier: MIT
with MC_Codec;
package body Pkg_Artifact_Grant with SPARK_Mode is
   use type Wide;
   procedure Encode(G : Grant; B : out Bytes; Used : out Natural; Status : out Outcome) is
      U : constant String:=MC_Text.Image(G.URL); F : Bytes(1..Maximum_Size):=(others=>0);
      Magic : constant String:="MCART002";
   begin
      B:=(others=>0); Used:=0; Status:=Invalid_Input;
      if G.Repository=Zero_Identity or else G.Object=Zero_Digest or else G.Snapshot=Zero_Digest or else G.Contract=Zero_Digest
        or else G.Revision=0 or else G.Expires<=G.Issued or else G.Expires-G.Issued>604_800
        or else G.Size<=0 or else G.Size>8*1024*1024*1024 or else not MC_Text.HTTPS_URL(U)
        or else B'Length<160+U'Length then return; end if;
      for I in Magic'Range loop F(I):=Byte(Character'Pos(Magic(I))); end loop;
      F(9..24):=G.Repository; F(25..56):=G.Object; F(57..88):=G.Snapshot; F(89..120):=G.Contract;
      MC_Codec.Put64(F,121,Wide(G.Revision)); MC_Codec.Put64(F,129,Wide(G.Issued));
      MC_Codec.Put64(F,137,Wide(G.Expires)); MC_Codec.Put64(F,145,Wide(G.Size)); MC_Codec.Put16(F,153,U'Length);
      for I in U'Range loop F(160+I):=Byte(Character'Pos(U(I))); end loop;
      Used:=160+U'Length; B(B'First..B'First+Used-1):=F(1..Used); Status:=OK;
   end;
   procedure Decode(B : Bytes; G : out Grant; Status : out Outcome) is
      F : Bytes(1..Maximum_Size):=(others=>0); Check : Bytes(1..Maximum_Size); N, Used : Natural;
   begin
      G:=(others=><>); Status:=Invalid_Input;
      if B'Length<170 or else B'Length>Maximum_Size then return; end if; F(1..B'Length):=B;
      for I in 0..3 loop if MC_Codec.U64(F,121+8*I)>Wide(Counter'Last) then return; end if; end loop;
      N:=MC_Codec.U16(F,153); if N>4_096 or else B'Length/=160+N then return; end if;
      G.Repository:=F(9..24); G.Object:=F(25..56); G.Snapshot:=F(57..88); G.Contract:=F(89..120);
      G.Revision:=Counter(MC_Codec.U64(F,121)); G.Issued:=Counter(MC_Codec.U64(F,129));
      G.Expires:=Counter(MC_Codec.U64(F,137)); G.Size:=Counter(MC_Codec.U64(F,145));
      declare Text_Length : constant Natural := N; U : String(1..Text_Length); begin
         for I in U'Range loop U(I):=Character'Val(F(160+I)); end loop;
         MC_Text.Set(G.URL,U,Status); if Status/=OK then return; end if;
      end;
      Encode(G,Check,Used,Status);
      if Status=OK and then (Used/=B'Length or else Check(1..Used)/=B) then Status:=Invalid_Input; end if;
   end;
end Pkg_Artifact_Grant;
