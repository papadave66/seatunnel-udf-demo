package com.example.demo;

import com.google.auto.service.AutoService;
import org.apache.seatunnel.api.table.type.SeaTunnelDataType;
import org.apache.seatunnel.transform.validator.ValidationContext;
import org.apache.seatunnel.transform.validator.ValidationResult;
import org.apache.seatunnel.transform.validator.udf.DataValidatorUDF;


@AutoService(DataValidatorUDF.class)
public class ExampleUDF implements DataValidatorUDF{

    @Override
    public String functionName() {
        return "TEST";
    }

    @Override
    public ValidationResult validate(Object value, SeaTunnelDataType<?> dataType, ValidationContext context) {
        if (value == null) {
            return ValidationResult.success();
        }

        String phone = value.toString().trim();

        // 自定义手机号验证逻辑
        if (phone.matches("^\\+?[1-9]\\d{1,14}$")) {
            return ValidationResult.success();
        } else {
            return ValidationResult.failure("手机号码格式无效: " + phone);
        }
    }

    @Override
    public String getDescription() {
        return DataValidatorUDF.super.getDescription();
    }
}
