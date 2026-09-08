-- SPDX-License-Identifier: MIT
with MC_Codec;
package body Resolver_Wire with SPARK_Mode is
   use type Byte; use type Word; use type Wide;
   Magic : constant Bytes := (77,67,82,83,79,76,48,49); -- MCRSOL01
   Plan_Magic : constant Bytes := (77,67,82,80,76,78,48,49); -- MCRPLN01
   procedure Encode (U : Universe; B : out Bytes; Used : out Natural; Status : out Outcome) is
      P : Positive;
      procedure N (X : Natural) with
        Pre => B'First=1 and then P<=B'Last and then B'Last-P>=3 and then P<=Positive'Last-4,
        Post => P=P'Old+4
      is begin MC_Codec.Put32 (B, P, Word (X)); P := P + 4; end;
      procedure C (X : Counter) with
        Pre => B'First=1 and then P<=B'Last and then B'Last-P>=7 and then P<=Positive'Last-8,
        Post => P=P'Old+8
      is begin MC_Codec.Put64 (B, P, Wide (X)); P := P + 8; end;
      procedure D (X : Digest) with
        Pre => B'First=1 and then P<=B'Last and then B'Last-P>=31 and then P<=Positive'Last-32,
        Post => P=P'Old+32
      is begin B (P .. P + 31) := X; P := P + 32; end;
   begin
      B := (others => 0); Used := 0; Status := Invalid_Input;
      if B'First /= 1 or else not Well_Formed (U) then return; end if;
      if B'Length < Size (U) then Status := Exhausted; return; end if;
      B (1 .. 8) := Magic; P := 9;
      D (U.Subject.Root); D (U.Subject.Boot); D (U.Subject.Snapshot); D (U.Subject.Policy);
      D (U.Subject.Adapter_Set); D (U.Subject.Native_Inventory); D (U.Subject.Configuration); D (U.Subject.Effect_Contracts);
      C (U.Subject.Generation); N (U.Item_Count); N (U.Node_Count); N (U.Rule_Count); N (U.Claim_Count);
      N (U.Maximum_Changes); C (U.Maximum_Transfer);
      for I in 1 .. U.Item_Count loop
         pragma Loop_Invariant(P=Header_Size+1+(I-1)*124);
         declare X : Item renames U.Items (I); begin
            D (X.Object_Hash); D (X.Metadata_Hash); D (X.Adapter_Hash);
            B (P) := Boolean'Pos (X.Initially_Present); B (P + 1) := Boolean'Pos (X.Permitted);
            B (P + 2) := Boolean'Pos (X.Reinstall_Requested); B (P + 3) := Pin_Mode'Pos (X.Pin); P := P + 4;
            C (X.Transfer_Bytes); N (X.Add_Pre); N (X.Add_Post); N (X.Remove_Pre); N (X.Remove_Post);
         end;
      end loop;
      for I in 1 .. U.Node_Count loop
         pragma Loop_Invariant(P=Header_Size+1+U.Item_Count*124+(I-1)*16);
         N (Operator'Pos (U.Nodes (I).Op)); N (U.Nodes (I).Subject); N (U.Nodes (I).Left); N (U.Nodes (I).Right);
      end loop;
      for I in 1 .. U.Rule_Count loop
         pragma Loop_Invariant(P=Header_Size+1+U.Item_Count*124+U.Node_Count*16+(I-1)*40);
         N (U.Rules (I).Predicate); N (Rule_Scope'Pos (U.Rules (I).Scope)); D (U.Rules (I).Origin);
      end loop;
      for I in 1 .. U.Claim_Count loop
         pragma Loop_Invariant(P=Header_Size+1+U.Item_Count*124+U.Node_Count*16+U.Rule_Count*40+(I-1)*104);
         D (U.Claims (I).Resource); D (U.Claims (I).Content); D (U.Claims (I).Attributes);
         N (U.Claims (I).Owner); N (Boolean'Pos (U.Claims (I).Shared_Identical));
      end loop;
      Used := P - 1; Status := OK;
   end Encode;
   procedure Decode (B : Bytes; U : out Universe; Status : out Outcome) is
      P : Positive range 1..Maximum_Universe_Bytes+1 := 9; Bad : Boolean := False;
      procedure N (Limit : Natural; Value : out Natural) with
        Pre => B'First=1 and then B'Length<=Maximum_Universe_Bytes,
        Post => P in P'Old..P'Old+4 and then Value<=Limit
          and then (if Bad'Old then Bad)
      is
         X : Word;
      begin
         Value:=0;
         if P > B'Last or else B'Last - P < 3 then Bad := True; return; end if;
         X := MC_Codec.U32 (B, P); P := P + 4;
         if X > Word (Limit) then Bad := True; return; end if; Value:=Natural(X);
      end;
      procedure C (Value : out Counter) with
        Pre => B'First=1 and then B'Length<=Maximum_Universe_Bytes,
        Post => P in P'Old..P'Old+8 and then (if Bad'Old then Bad)
      is
         X : Wide;
      begin
         Value:=0;
         if P > B'Last or else B'Last - P < 7 then Bad := True; return; end if;
         X := MC_Codec.U64 (B, P); P := P + 8;
         if X > Wide (Counter'Last) then Bad := True; return; end if; Value:=Counter(X);
      end;
      procedure D (Value : out Digest) with
        Pre => B'First=1 and then B'Length<=Maximum_Universe_Bytes,
        Post => P in P'Old..P'Old+32 and then (if Bad'Old then Bad)
      is
      begin
         Value:=Zero_Digest;
         if P > B'Last or else B'Last - P < 31 then Bad := True; return; end if;
         Value := B (P .. P + 31); P := P + 32;
      end;
      procedure Byte_Value (Limit : Byte; Value : out Natural) with
        Pre => B'First=1 and then B'Length<=Maximum_Universe_Bytes,
        Post => P in P'Old..P'Old+1 and then Value<=Natural(Limit)
          and then (if Bad'Old then Bad)
      is
         X : Byte;
      begin
         Value:=0;
         if P > B'Last then Bad := True; return; end if;
         X := B (P); P := P + 1;
         if X > Limit then Bad := True; return; end if; Value:=Natural(X);
      end;
      Small : Natural;
   begin
      U := (others => <>); Status := Invalid_Input;
      if B'First /= 1 or else B'Length < Header_Size or else B'Length > Maximum_Universe_Bytes
         or else B (1 .. 8) /= Magic then return; end if;
      D (U.Subject.Root); D (U.Subject.Boot); D (U.Subject.Snapshot); D (U.Subject.Policy);
      D (U.Subject.Adapter_Set); D (U.Subject.Native_Inventory);
      D (U.Subject.Configuration); D (U.Subject.Effect_Contracts);
      C (U.Subject.Generation); N (Max_Items,U.Item_Count); N (Max_Nodes,U.Node_Count);
      N (Max_Rules,U.Rule_Count); N (Max_Claims,U.Claim_Count);
      N (Max_Steps,U.Maximum_Changes); C (U.Maximum_Transfer);
      if Bad or else B'Length /= Size (U) then return; end if;
      for I in 1 .. U.Item_Count loop
         D (U.Items (I).Object_Hash); D (U.Items (I).Metadata_Hash); D (U.Items (I).Adapter_Hash);
         Byte_Value (1,Small); U.Items (I).Initially_Present := Boolean'Val(Small);
         Byte_Value (1,Small); U.Items (I).Permitted := Boolean'Val(Small);
         Byte_Value (1,Small); U.Items (I).Reinstall_Requested := Boolean'Val(Small);
         Byte_Value (3,Small); U.Items (I).Pin := Pin_Mode'Val(Small); C (U.Items (I).Transfer_Bytes);
         N (Max_Nodes,U.Items (I).Add_Pre); N (Max_Nodes,U.Items (I).Add_Post);
         N (Max_Nodes,U.Items (I).Remove_Pre); N (Max_Nodes,U.Items (I).Remove_Post);
      end loop;
      for I in 1 .. U.Node_Count loop
         N (5,Small); U.Nodes (I).Op := Operator'Val(Small); N (Max_Items,U.Nodes (I).Subject);
         N (Max_Nodes,U.Nodes (I).Left); N (Max_Nodes,U.Nodes (I).Right);
      end loop;
      for I in 1 .. U.Rule_Count loop
         N (Max_Nodes,U.Rules (I).Predicate); N (1,Small); U.Rules (I).Scope := Rule_Scope'Val(Small); D (U.Rules (I).Origin);
      end loop;
      for I in 1 .. U.Claim_Count loop
         D (U.Claims (I).Resource); D (U.Claims (I).Content); D (U.Claims (I).Attributes);
         N (Max_Items,U.Claims (I).Owner); N (1,Small); U.Claims (I).Shared_Identical := Boolean'Val(Small);
      end loop;
      if not Bad and then P = B'Last + 1 and then Well_Formed (U) then Status := OK; end if;
   end Decode;
   procedure Encode_Proposal (P : Proposal; Item_Count : Item_ID;
      B : out Bytes; Used : out Natural; Status : out Outcome) is
      Pos : Positive; Required : constant Natural := 48 + Item_Count + P.Count * 8;
   begin
      B := (others => 0); Used := 0; Status := Invalid_Input;
      if B'First /= 1 or else Is_Zero (P.Universe_Hash) then return; end if;
      if B'Length < Required then Status := Exhausted; return; end if;
      for I in Item_Count + 1 .. Max_Items loop if P.Selected (I) then return; end if; end loop;
      B (1 .. 8) := Plan_Magic; B (9 .. 40) := P.Universe_Hash;
      MC_Codec.Put32 (B, 41, Word (Item_Count)); Pos := 45;
      for I in 1 .. Item_Count loop
         pragma Loop_Invariant(Pos=44+I);
         B (Pos) := Boolean'Pos (P.Selected (I)); Pos := Pos + 1;
      end loop;
      MC_Codec.Put32 (B, Pos, Word (P.Count)); Pos := Pos + 4;
      for I in 1 .. P.Count loop
         pragma Loop_Invariant(Pos=49+Item_Count+(I-1)*8);
         if P.Steps (I).Subject = 0 or else P.Steps (I).Subject > Item_Count then return; end if;
         MC_Codec.Put32 (B, Pos, Word (Action_Kind'Pos (P.Steps (I).Kind)));
         MC_Codec.Put32 (B, Pos + 4, Word (P.Steps (I).Subject)); Pos := Pos + 8;
      end loop;
      Used := Pos - 1; Status := OK;
   end Encode_Proposal;
   procedure Decode_Proposal (B : Bytes; Item_Count : Item_ID;
      P : out Proposal; Status : out Outcome) is
      Pos : Positive := 45; X, Y : Word;
   begin
      P := (others => <>); Status := Invalid_Input;
      if B'First /= 1 or else B'Length < 48 + Item_Count or else B'Length > Maximum_Proposal_Bytes
        or else B (1 .. 8) /= Plan_Magic or else MC_Codec.U32 (B, 41) /= Word (Item_Count) then return; end if;
      P.Universe_Hash := B (9 .. 40); if Is_Zero (P.Universe_Hash) then return; end if;
      for I in 1 .. Item_Count loop
         pragma Loop_Invariant(Pos=44+I);
         if B (Pos) > 1 then return; end if; P.Selected (I) := B (Pos) = 1; Pos := Pos + 1;
      end loop;
      X := MC_Codec.U32 (B, Pos); Pos := Pos + 4; if X > Max_Steps then return; end if;
      P.Count := Natural (X); if B'Length /= 48 + Item_Count + P.Count * 8 then return; end if;
      for I in 1 .. P.Count loop
         pragma Loop_Invariant(Pos=49+Item_Count+(I-1)*8);
         X := MC_Codec.U32 (B, Pos); Y := MC_Codec.U32 (B, Pos + 4); Pos := Pos + 8;
         if X > 2 or else Y = 0 or else Y > Word (Item_Count) then return; end if;
         P.Steps (I) := (Action_Kind'Val (X), Item_ID (Y));
      end loop;
      Status := OK;
   end Decode_Proposal;
end Resolver_Wire;
