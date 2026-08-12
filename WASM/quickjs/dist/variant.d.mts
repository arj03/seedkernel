declare const variant: {
    readonly type: "sync";
    readonly importFFI: () => Promise<new (module: unknown) => unknown>;
    readonly importModuleLoader: () => Promise<unknown>;
};
export default variant;
