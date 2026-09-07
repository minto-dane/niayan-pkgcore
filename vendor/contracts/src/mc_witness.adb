-- SPDX-License-Identifier: MIT
with MC_Codec;
package body MC_Witness with SPARK_Mode is
   use type Wide;
   Magic : constant Bytes:=(16#4D#,16#43#,16#57#,16#49#,16#54#,16#30#,16#30#,16#32#);
   function Encode(S : Statement) return Frame is B : Frame:=(others=>0); begin
      B(1..8):=Magic; B(9):=Byte(Fact'Pos(S.Kind)); B(17..32):=S.Cluster_ID;
      B(33..48):=S.Node_ID; B(49..64):=S.Root_ID; B(65..80):=S.Transaction_ID;
      B(81..96):=S.Boot_ID; B(97..128):=S.Plan; B(129..160):=S.Contract;
      MC_Codec.Put64(B,161,Wide(S.Epoch)); MC_Codec.Put64(B,169,Wide(S.Token));
      MC_Codec.Put64(B,177,Wide(S.Issued)); MC_Codec.Put64(B,185,Wide(S.Expires)); return B;
   end;
   procedure Decode(B : Bytes; S : out Statement; Status : out Outcome) is
      type Offsets is array(1..4) of Positive; Check : constant Offsets:=(161,169,177,185);
   begin
      S:=(others=><>); Status:=Invalid_Input;
      if B'First/=1 or else B'Length/=224 or else B(1..8)/=Magic or else Natural(B(9))>Fact'Pos(Fact'Last) then return; end if;
      for J in 10..16 loop if B(J)/=0 then return; end if; end loop;
      for J in 193..224 loop if B(J)/=0 then return; end if; end loop;
      for O of Check loop if MC_Codec.U64(B,O)>Wide(Counter'Last) then return; end if; end loop;
      S.Kind:=Fact'Val(B(9)); S.Cluster_ID:=B(17..32); S.Node_ID:=B(33..48); S.Root_ID:=B(49..64);
      S.Transaction_ID:=B(65..80); S.Boot_ID:=B(81..96); S.Plan:=B(97..128); S.Contract:=B(129..160);
      S.Epoch:=Counter(MC_Codec.U64(B,161)); S.Token:=Counter(MC_Codec.U64(B,169));
      S.Issued:=Counter(MC_Codec.U64(B,177)); S.Expires:=Counter(MC_Codec.U64(B,185)); Status:=OK;
   end;
   function Matches(S, Expected : Statement; Now, Maximum_Age : Counter) return Boolean is
     (S.Kind=Expected.Kind and then S.Cluster_ID=Expected.Cluster_ID and then S.Node_ID=Expected.Node_ID
       and then S.Root_ID=Expected.Root_ID and then S.Transaction_ID=Expected.Transaction_ID
       and then S.Boot_ID=Expected.Boot_ID and then S.Plan=Expected.Plan and then S.Contract=Expected.Contract
       and then S.Epoch=Expected.Epoch and then S.Token=Expected.Token
       and then S.Issued<=Now and then Now<S.Expires and then S.Expires-S.Issued<=Maximum_Age);
end MC_Witness;
