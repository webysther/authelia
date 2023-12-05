import React, { Fragment, useCallback, useEffect, useState } from "react";

import { faTimesCircle } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
    Box,
    Button,
    CircularProgress,
    Dialog,
    DialogActions,
    DialogContent,
    DialogContentText,
    DialogTitle,
    FormControl,
    FormControlLabel,
    FormLabel,
    Link,
    Radio,
    RadioGroup,
    Step,
    StepLabel,
    Stepper,
    Switch,
    TextField,
    Theme,
    Typography,
} from "@mui/material";
import { red } from "@mui/material/colors";
import Grid from "@mui/material/Unstable_Grid2";
import makeStyles from "@mui/styles/makeStyles";
import classnames from "classnames";
import { QRCodeSVG } from "qrcode.react";
import { useTranslation } from "react-i18next";

import AppStoreBadges from "@components/AppStoreBadges";
import CopyButton from "@components/CopyButton";
import SuccessIcon from "@components/SuccessIcon";
import { GoogleAuthenticator } from "@constants/constants";
import { useNotifications } from "@hooks/NotificationsContext";
import { toAlgorithmString } from "@models/TOTPConfiguration";
import { completeTOTPRegister, stopTOTPRegister } from "@services/OneTimePassword";
import { getTOTPSecret } from "@services/RegisterDevice";
import { getTOTPOptions } from "@services/UserInfoTOTPConfiguration";
import { State } from "@views/LoginPortal/SecondFactor/OneTimePasswordMethod";
import OTPDial from "@views/LoginPortal/SecondFactor/OTPDial";

const steps = ["Start", "Register", "Confirm"];

interface Props {
    open: boolean;
    setClosed: () => void;
}

interface Options {
    algorithm: string;
    length: number;
    period: number;
}

interface AvailableOptions {
    algorithms: string[];
    lengths: number[];
    periods: number[];
}

const TOTPRegisterDialog = function (props: Props) {
    const { t: translate } = useTranslation("settings");

    const styles = useStyles();
    const { createErrorNotification } = useNotifications();

    const [selected, setSelected] = useState<Options>({ algorithm: "", length: 6, period: 30 });
    const [defaults, setDefaults] = useState<Options | null>(null);
    const [available, setAvailable] = useState<AvailableOptions>({
        algorithms: [],
        lengths: [],
        periods: [],
    });

    const [activeStep, setActiveStep] = useState(0);

    const [secretURL, setSecretURL] = useState<string | null>(null);
    const [secretValue, setSecretValue] = useState<string | null>(null);
    const [isLoading, setIsLoading] = useState(false);
    const [showAdvanced, setShowAdvanced] = useState(false);
    const [hasErrored, setHasErrored] = useState(false);
    const [dialValue, setDialValue] = useState("");
    const [dialState, setDialState] = useState(State.Idle);
    const [showQRCode, setShowQRCode] = useState(true);
    const [success, setSuccess] = useState(false);

    const resetStates = useCallback(() => {
        if (defaults) {
            setSelected(defaults);
        }

        setSecretURL(null);
        setSecretValue(null);
        setIsLoading(false);
        setShowAdvanced(false);
        setActiveStep(0);
        setDialValue("");
        setDialState(State.Idle);
        setShowQRCode(true);
    }, [defaults]);

    const handleClose = useCallback(() => {
        (async () => {
            props.setClosed();

            if (secretURL !== "") {
                try {
                    await stopTOTPRegister();
                } catch (err) {
                    console.error(err);
                }
            }

            resetStates();
        })();
    }, [props, secretURL, resetStates]);

    const handleFinished = useCallback(() => {
        setSuccess(true);

        setTimeout(() => {
            props.setClosed();
            resetStates();
        }, 750);
    }, [props, resetStates]);

    const handleOnClose = () => {
        if (!props.open) {
            return;
        }

        handleClose();
    };

    useEffect(() => {
        if (!props.open || activeStep !== 0 || defaults !== null) {
            return;
        }

        (async () => {
            const opts = await getTOTPOptions();

            const decoded = {
                algorithm: toAlgorithmString(opts.algorithm),
                length: opts.length,
                period: opts.period,
            };

            setAvailable({
                algorithms: opts.algorithms.map((algorithm) => toAlgorithmString(algorithm)),
                lengths: opts.lengths,
                periods: opts.periods,
            });

            setDefaults(decoded);
            setSelected(decoded);
        })();
    }, [props.open, activeStep, defaults, selected]);

    const handleSetStepPrevious = useCallback(() => {
        if (activeStep === 0) {
            return;
        }

        setShowAdvanced(false);
        setActiveStep((prevState) => {
            return prevState - 1;
        });
    }, [activeStep]);

    const handleSetStepNext = useCallback(() => {
        if (activeStep === steps.length - 1) {
            return;
        }

        setShowAdvanced(false);
        setActiveStep((prevState) => {
            return prevState + 1;
        });
    }, [activeStep]);

    useEffect(() => {
        if (!props.open || activeStep !== 1) {
            return;
        }

        (async () => {
            setIsLoading(true);

            try {
                const secret = await getTOTPSecret(selected.algorithm, selected.length, selected.period);
                setSecretURL(secret.otpauth_url);
                setSecretValue(secret.base32_secret);
            } catch (err) {
                console.error(err);
                if ((err as Error).message.includes("Request failed with status code 403")) {
                    createErrorNotification(
                        translate(
                            "You must open the link from the same device and browser that initiated the registration process",
                        ),
                    );
                } else {
                    createErrorNotification(
                        translate("Failed to register device, the provided link is expired or has already been used"),
                    );
                }
                setHasErrored(true);
            }

            setIsLoading(false);
        })();
    }, [activeStep, createErrorNotification, selected, props.open, translate]);

    useEffect(() => {
        if (!props.open || activeStep !== 2 || dialState === State.InProgress || dialValue.length !== selected.length) {
            return;
        }

        (async () => {
            setDialState(State.InProgress);

            try {
                const registerValue = dialValue;
                setDialValue("");

                await completeTOTPRegister(registerValue);

                handleFinished();
            } catch (err) {
                console.error(err);
                setDialState(State.Failure);
            }
        })();
    }, [activeStep, dialState, dialValue, dialValue.length, handleFinished, props.open, selected.length]);

    const toggleAdvanced = () => {
        setShowAdvanced((prevState) => !prevState);
    };

    const advanced =
        defaults !== null &&
        (available.algorithms.length !== 1 || available.lengths.length !== 1 || available.periods.length !== 1);

    const disableAdvanced =
        defaults === null ||
        (available.algorithms.length <= 1 && available.lengths.length <= 1 && available.periods.length <= 1);

    const hideAlgorithms = advanced && available.algorithms.length <= 1;
    const hideLengths = advanced && available.lengths.length <= 1;
    const hidePeriods = advanced && available.periods.length <= 1;
    const qrcodeFuzzyStyle = isLoading || hasErrored ? styles.fuzzy : undefined;

    function renderStep(step: number) {
        switch (step) {
            case 0:
                return (
                    <Fragment>
                        {defaults === null ? (
                            <Grid xs={12} my={3}>
                                <Typography>Loading...</Typography>
                            </Grid>
                        ) : (
                            <Grid container>
                                <Grid xs={12} my={3}>
                                    <Typography>{translate("To begin select next")}</Typography>
                                </Grid>
                                <Grid xs={12} hidden={disableAdvanced}>
                                    <FormControlLabel
                                        disabled={disableAdvanced}
                                        control={<Switch checked={showAdvanced} onChange={toggleAdvanced} />}
                                        label={translate("Advanced")}
                                    />
                                </Grid>
                                <Grid
                                    xs={12}
                                    hidden={disableAdvanced || !showAdvanced}
                                    justifyContent={"center"}
                                    alignItems={"center"}
                                >
                                    <FormControl fullWidth>
                                        <FormLabel id={"lbl-adv-algorithms"} hidden={hideAlgorithms}>
                                            {translate("Algorithm")}
                                        </FormLabel>
                                        <RadioGroup
                                            row
                                            aria-labelledby={"lbl-adv-algorithms"}
                                            value={selected.algorithm}
                                            hidden={hideAlgorithms}
                                            style={{
                                                justifyContent: "center",
                                            }}
                                            onChange={(e, value) => {
                                                setSelected((prevState) => {
                                                    return {
                                                        ...prevState,
                                                        algorithm: value,
                                                    };
                                                });

                                                e.preventDefault();
                                            }}
                                        >
                                            {available.algorithms.map((algorithm) => (
                                                <FormControlLabel
                                                    key={algorithm}
                                                    value={algorithm}
                                                    control={<Radio />}
                                                    label={algorithm}
                                                />
                                            ))}
                                        </RadioGroup>
                                        <FormLabel id={"lbl-adv-lengths"} hidden={hideLengths}>
                                            {translate("Length")}
                                        </FormLabel>
                                        <RadioGroup
                                            row
                                            aria-labelledby={"lbl-adv-lengths"}
                                            value={selected.length.toString()}
                                            hidden={hideLengths}
                                            style={{
                                                justifyContent: "center",
                                            }}
                                            onChange={(e, value) => {
                                                setSelected((prevState) => {
                                                    return {
                                                        ...prevState,
                                                        length: parseInt(value),
                                                    };
                                                });

                                                e.preventDefault();
                                            }}
                                        >
                                            {available.lengths.map((length) => (
                                                <FormControlLabel
                                                    key={length.toString()}
                                                    value={length.toString()}
                                                    control={<Radio />}
                                                    label={length.toString()}
                                                />
                                            ))}
                                        </RadioGroup>
                                        <FormLabel id={"lbl-adv-periods"} hidden={hidePeriods}>
                                            {translate("Seconds")}
                                        </FormLabel>
                                        <RadioGroup
                                            row
                                            aria-labelledby={"lbl-adv-periods"}
                                            value={selected.period.toString()}
                                            hidden={hidePeriods}
                                            style={{
                                                justifyContent: "center",
                                            }}
                                            onChange={(e, value) => {
                                                setSelected((prevState) => {
                                                    return {
                                                        ...prevState,
                                                        period: parseInt(value),
                                                    };
                                                });

                                                e.preventDefault();
                                            }}
                                        >
                                            {available.periods.map((period) => (
                                                <FormControlLabel
                                                    key={period.toString()}
                                                    value={period.toString()}
                                                    control={<Radio />}
                                                    label={period.toString()}
                                                />
                                            ))}
                                        </RadioGroup>
                                    </FormControl>
                                </Grid>
                            </Grid>
                        )}
                    </Fragment>
                );
            case 1:
                return (
                    <Fragment>
                        <Grid xs={12} my={2}>
                            <FormControlLabel
                                disabled={disableAdvanced}
                                control={
                                    <Switch
                                        checked={showQRCode}
                                        onChange={() => {
                                            setShowQRCode((value) => !value);
                                        }}
                                    />
                                }
                                label={translate("QR Code")}
                            />
                        </Grid>
                        <Grid xs={12} hidden={!showQRCode}>
                            <Box className={classnames(qrcodeFuzzyStyle, styles.qrcodeContainer)}>
                                {secretURL !== null ? (
                                    <Link href={secretURL} underline="hover">
                                        <QRCodeSVG value={secretURL} className={styles.qrcode} size={200} />
                                        {!hasErrored && isLoading ? (
                                            <CircularProgress className={styles.loader} size={128} />
                                        ) : null}
                                        {hasErrored ? (
                                            <FontAwesomeIcon className={styles.failureIcon} icon={faTimesCircle} />
                                        ) : null}
                                    </Link>
                                ) : null}
                            </Box>
                        </Grid>
                        <Grid xs={12} hidden={showQRCode}>
                            <Grid container spacing={2} justifyContent={"center"}>
                                <Grid xs={4}>
                                    <CopyButton
                                        tooltip={translate("Click to Copy")}
                                        value={secretURL}
                                        childrenCopied={translate("Copied")}
                                        fullWidth={true}
                                    >
                                        {translate("OTP URL")}
                                    </CopyButton>
                                </Grid>
                                <Grid xs={4}>
                                    <CopyButton
                                        tooltip={translate("Click to Copy")}
                                        value={secretValue}
                                        childrenCopied={translate("Copied")}
                                        fullWidth={true}
                                    >
                                        {translate("Secret")}
                                    </CopyButton>
                                </Grid>
                                <Grid xs={12}>
                                    <TextField
                                        id="secret-url"
                                        label={translate("Secret")}
                                        className={styles.secret}
                                        value={secretURL === null ? "" : secretURL}
                                        multiline={true}
                                        InputProps={{
                                            readOnly: true,
                                        }}
                                    />
                                </Grid>
                            </Grid>
                        </Grid>
                        <Grid xs={12} sx={{ display: { xs: "none", md: "block" } }}>
                            <Box>
                                <Typography className={styles.googleAuthenticatorText}>
                                    {translate("Need Google Authenticator?")}
                                </Typography>
                                <AppStoreBadges
                                    iconSize={110}
                                    targetBlank
                                    className={styles.googleAuthenticatorBadges}
                                    googlePlayLink={GoogleAuthenticator.googlePlay}
                                    appleStoreLink={GoogleAuthenticator.appleStore}
                                />
                            </Box>
                        </Grid>
                    </Fragment>
                );
            case 2:
                return (
                    <Fragment>
                        <Grid xs={12} paddingY={4}>
                            {success ? (
                                <Box className={styles.success}>
                                    <SuccessIcon />
                                </Box>
                            ) : (
                                <OTPDial
                                    passcode={dialValue}
                                    state={dialState}
                                    digits={selected.length}
                                    period={selected.period}
                                    onChange={setDialValue}
                                />
                            )}
                        </Grid>
                    </Fragment>
                );
        }
    }

    return (
        <Dialog open={props.open} onClose={handleOnClose} maxWidth={"lg"} fullWidth={true}>
            <DialogTitle>{translate("Register One Time Password (TOTP)")}</DialogTitle>
            <DialogContent>
                <DialogContentText sx={{ mb: 3 }}>
                    {translate("This dialog allows registration of the One-Time Password.")}
                </DialogContentText>
                <Grid container spacing={0} alignItems={"center"} justifyContent={"center"} textAlign={"center"}>
                    <Grid xs={12}>
                        <Stepper activeStep={activeStep}>
                            {steps.map((label, index) => {
                                const stepProps: { completed?: boolean } = {};
                                const labelProps: {
                                    optional?: React.ReactNode;
                                } = {};
                                return (
                                    <Step key={label} {...stepProps}>
                                        <StepLabel {...labelProps}>{translate(label)}</StepLabel>
                                    </Step>
                                );
                            })}
                        </Stepper>
                    </Grid>
                    <Grid xs={12}>
                        <Grid container spacing={1} justifyContent={"center"}>
                            {renderStep(activeStep)}
                        </Grid>
                    </Grid>
                </Grid>
            </DialogContent>
            <DialogActions>
                <Button color={"primary"} onClick={handleSetStepPrevious} disabled={activeStep === 0}>
                    {translate("Previous")}
                </Button>
                <Button color={"error"} onClick={handleClose}>
                    {translate("Cancel")}
                </Button>
                <Button color={"primary"} onClick={handleSetStepNext} disabled={activeStep === steps.length - 1}>
                    {translate("Next")}
                </Button>
            </DialogActions>
        </Dialog>
    );
};

const useStyles = makeStyles((theme: Theme) => ({
    qrcode: {
        marginTop: theme.spacing(2),
        marginBottom: theme.spacing(2),
        padding: theme.spacing(),
        backgroundColor: "white",
    },
    fuzzy: {
        filter: "blur(10px)",
    },
    secret: {
        marginTop: theme.spacing(1),
        marginBottom: theme.spacing(1),
        width: "256px",
    },
    googleAuthenticatorText: {
        fontSize: theme.typography.fontSize * 0.8,
    },
    googleAuthenticatorBadges: {},
    qrcodeContainer: {
        position: "relative",
        display: "inline-block",
    },
    loader: {
        position: "absolute",
        top: "calc(128px - 64px)",
        left: "calc(128px - 64px)",
        color: "rgba(255, 255, 255, 0.5)",
    },
    failureIcon: {
        position: "absolute",
        top: "calc(128px - 64px)",
        left: "calc(128px - 64px)",
        color: red[400],
        fontSize: "128px",
    },
    success: {
        marginBottom: theme.spacing(2),
        flex: "0 0 100%",
    },
}));

export default TOTPRegisterDialog;
