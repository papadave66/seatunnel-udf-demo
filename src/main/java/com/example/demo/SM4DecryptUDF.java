package com.example.demo;

import com.example.demo.utils.SM4Util;
import com.google.auto.service.AutoService;
import org.apache.commons.collections4.IterableUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.seatunnel.api.table.type.BasicType;
import org.apache.seatunnel.api.table.type.SeaTunnelDataType;
import org.apache.seatunnel.transform.sql.zeta.ZetaUDF;

import java.util.List;

@AutoService(ZetaUDF.class)
public class SM4DecryptUDF implements ZetaUDF {

    @Override
    public String functionName() {
        return "SM4_DECRYPT";
    }

    @Override
    public SeaTunnelDataType<?> resultType(List<SeaTunnelDataType<?>> list) {
        return BasicType.STRING_TYPE;
    }

    @Override
    public Object evaluate(List<Object> list) {
        String arg = (String) IterableUtils.get(list, 0);
        if (StringUtils.isEmpty(arg)) return null;
        return SM4Util.decryECBSM4(arg, SM4Util.KEY);
    }
}
