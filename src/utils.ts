export const dateToSeconds = (date: Date): number =>
  Math.floor(date.getTime() / 1000);
