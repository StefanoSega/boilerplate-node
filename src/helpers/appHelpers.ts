export const onExitingApp = (callback: () => Promise<void>) => {
  [
    `exit`,
    `SIGINT`,
    `SIGUSR1`,
    `SIGUSR2`,
    `uncaughtException`,
    `SIGTERM`,
  ].forEach((eventType) => {
    process.on(eventType, async () => {
      await callback();

      process.exit(1);
    });
  });
};
