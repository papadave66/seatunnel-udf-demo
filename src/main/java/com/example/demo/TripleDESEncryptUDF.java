package com.example.demo;

import com.example.demo.utils.TripleDESUtil;
import com.google.auto.service.AutoService;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.seatunnel.api.table.type.BasicType;
import org.apache.seatunnel.api.table.type.SeaTunnelDataType;
import org.apache.seatunnel.transform.sql.zeta.ZetaUDF;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;


@AutoService(ZetaUDF.class)
public class TripleDESEncryptUDF implements ZetaUDF {

    @Override
    public String functionName() {
        return "TRIPLEDES_ENCRYPT";
    }

    @Override
    public SeaTunnelDataType<?> resultType(List<SeaTunnelDataType<?>> list) {
        return BasicType.STRING_TYPE;
    }

    @Override
    public Object evaluate(List<Object> list) {
        if (CollectionUtils.isEmpty(list)) {
            return null;
        }
        String merged = StringUtils.join(
                list.stream()
                        .filter(Objects::nonNull)
                        .map(Object::toString)
                        .collect(Collectors.toList())
        );

        if (StringUtils.isBlank(merged)) {
            return null;
        }
        return TripleDESUtil.encrypt(merged, TripleDESUtil.KEY);
    }
}
