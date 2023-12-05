import React, { Fragment } from "react";

import { Link, LinkProps } from "@mui/material";
import { useTranslation } from "react-i18next";

import { getPrivacyPolicyURL } from "@utils/Configuration";

const PrivacyPolicyLink = function (props: LinkProps) {
    const { t: translate } = useTranslation();

    const hrefPrivacyPolicy = getPrivacyPolicyURL();

    return (
        <Fragment>
            <Link {...props} href={hrefPrivacyPolicy} target="_blank" rel="noopener" underline="hover">
                {translate("Privacy Policy")}
            </Link>
        </Fragment>
    );
};

export default PrivacyPolicyLink;
