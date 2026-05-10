export function isExpired(date: Date): boolean {
    return date.getTime() < Date.now();
}

export function relativeLabel(date: Date): string {
    const diffMs = date.getTime() - Date.now();
    const diffSeconds = Math.round(diffMs / 1000);
    const abs = Math.abs(diffSeconds);
    const future = diffSeconds >= 0;

    if (abs < 60) return future ? 'in a few seconds' : 'just expired';

    if (abs < 3600) {
        const mins = Math.round(abs / 60);
        const unit = mins === 1 ? 'minute' : 'minutes';
        return future ? `valid for ${mins} ${unit}` : `expired ${mins} ${unit} ago`;
    }

    if (abs < 86400) {
        const hours = Math.round(abs / 3600);
        const unit = hours === 1 ? 'hour' : 'hours';
        return future ? `valid for ${hours} ${unit}` : `expired ${hours} ${unit} ago`;
    }

    const days = Math.round(abs / 86400);
    const unit = days === 1 ? 'day' : 'days';
    return future ? `valid for ${days} ${unit}` : `expired ${days} ${unit} ago`;
}
