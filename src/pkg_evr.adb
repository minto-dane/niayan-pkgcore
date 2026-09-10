-- SPDX-License-Identifier: BSD-3-Clause
package body Pkg_EVR with SPARK_Mode is
   use type Pkg_Versions.Ordering;
   procedure Parse(S : String; V : out EVR; Status : out Outcome) is
      Colon, Dash : Natural:=0; Start : Positive; Digit : Counter;
   begin
      V:=(others=><>); Status:=Invalid_Input;
      if S'Length=0 or else S'Length>4096 then return; end if;
      Start:=S'First;
      for J in S'Range loop
         pragma Loop_Invariant(Colon=0 or else Colon in S'First..J-1);
         pragma Loop_Invariant(Dash=0 or else Dash in S'First..J-1);
         if S(J)=':' then if Colon/=0 then return; end if; Colon:=J; end if;
         if S(J)='-' then Dash:=J; end if;
         if Character'Pos(S(J))<=32 or else Character'Pos(S(J))>126 then return; end if;
      end loop;
      if Colon/=0 then
         if Colon=S'First or else Colon=S'Last then return; end if;
         for J in S'First..Colon-1 loop
            if S(J) not in '0'..'9' then return; end if;
            Digit:=Counter(Character'Pos(S(J))-Character'Pos('0'));
            if V.Epoch>(Counter'Last-Digit)/10 then return; end if;
            V.Epoch:=V.Epoch*10+Digit;
         end loop;
         Start:=Colon+1;
      end if;
      if Dash=0 then MC_Text.Set(V.Version,S(Start..S'Last),Status);
      else
         if Dash<=Start or else Dash=S'Last then return; end if;
         MC_Text.Set(V.Version,S(Start..Dash-1),Status);
         if Status=OK then MC_Text.Set(V.Release,S(Dash+1..S'Last),Status); end if;
      end if;
   end;
   function Compare(A,B : EVR; Dependency_Match : Boolean:=False) return Pkg_Versions.Ordering is
      O : Pkg_Versions.Ordering;
   begin
      if A.Epoch<B.Epoch then return Pkg_Versions.Older; elsif A.Epoch>B.Epoch then return Pkg_Versions.Newer; end if;
      O:=Pkg_Versions.Compare(MC_Text.Image(A.Version),MC_Text.Image(B.Version));
      if O/=Pkg_Versions.Equal then return O; end if;
      if Dependency_Match and then (MC_Text.Length(A.Release)=0 or else MC_Text.Length(B.Release)=0)
      then return Pkg_Versions.Equal; end if;
      return Pkg_Versions.Compare(MC_Text.Image(A.Release),MC_Text.Image(B.Release));
   end;
end Pkg_EVR;
