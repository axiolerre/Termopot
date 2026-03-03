PROGRAM Termo_Logic
  VAR
    Current_Temp_WC AT %MW0 : INT := 18;
    Target_Temp_WC AT %MW1 : INT := 18;
    Heater_Status_WC AT %QX0.0 : BOOL;

    Current_Temp_Conf AT %MW2 : INT := 23;
    Target_Temp_Conf AT %MW3 : INT := 23;
    Heater_Status_Conf AT %QX0.1 : BOOL;

    Current_Temp_Acc AT %MW4 : INT := 20;
    Target_Temp_Acc AT %MW5 : INT := 20;
    Heater_Status_Acc AT %QX0.2 : BOOL;
  END_VAR
  
  VAR
    Seed_WC : DINT := 42; 
    Update_Temp_WC : BOOL;
    Seed_Conf : DINT := 42; 
    Update_Temp_Conf : BOOL;
    Seed_Acc : DINT := 42; 
    Update_Temp_Acc : BOOL;
  END_VAR

  Seed_WC := (Seed_WC * 25173 + 13849) MOD 65536;
  Seed_Conf := (Seed_Conf * 25173 + 13849) MOD 65536;
  Seed_Acc := (Seed_Acc * 25173 + 13849) MOD 65536;

  Update_Temp_WC := ((Seed_WC MOD 10) = 0);
  Update_Temp_Conf := ((Seed_Conf MOD 10) = 0);
  Update_Temp_Acc := ((Seed_Acc MOD 10) = 0);

  IF Current_Temp_WC < Target_Temp_WC THEN
    Heater_Status_WC := TRUE;
  ELSE
    Heater_Status_WC := FALSE;
  END_IF;

  IF Update_Temp_WC THEN
    IF Current_Temp_WC < Target_Temp_WC THEN
      Current_Temp_WC := Current_Temp_WC + 1;
    ELSIF Current_Temp_WC > Target_Temp_WC THEN
      Current_Temp_WC := Current_Temp_WC - 1;
    END_IF;
  END_IF;

  IF Current_Temp_Conf < Target_Temp_Conf THEN
    Heater_Status_Conf := TRUE;
  ELSE
    Heater_Status_Conf := FALSE;
  END_IF;

  IF Update_Temp_Conf THEN
    IF Current_Temp_Conf < Target_Temp_Conf THEN
      Current_Temp_Conf := Current_Temp_Conf + 1;
    ELSIF Current_Temp_Conf > Target_Temp_Conf THEN
      Current_Temp_Conf := Current_Temp_Conf - 1;
    END_IF;
  END_IF;

  IF Current_Temp_Acc < Target_Temp_Acc THEN
    Heater_Status_Acc := TRUE;
  ELSE
    Heater_Status_Acc := FALSE;
  END_IF;

  IF Update_Temp_Acc THEN
    IF Current_Temp_Acc < Target_Temp_Acc THEN
      Current_Temp_Acc := Current_Temp_Acc + 1;
    ELSIF Current_Temp_Acc > Target_Temp_Acc THEN
      Current_Temp_Acc := Current_Temp_Acc - 1;
    END_IF;
  END_IF;

END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#1000ms, PRIORITY := 0);
    PROGRAM instance0 WITH task0 : Termo_Logic;
  END_RESOURCE
END_CONFIGURATION